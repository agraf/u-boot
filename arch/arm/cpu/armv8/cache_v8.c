/*
 * (C) Copyright 2013
 * David Feng <fenghua@phytium.com.cn>
 *
 * (C) Copyright 2016
 * Alexander Graf <agraf@suse.de>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <common.h>
#include <asm/system.h>
#include <asm/armv8/mmu.h>

/* #define DEBUG_MMU */

#ifdef DEBUG_MMU
#define DPRINTF(a, ...) printf("%s:%d: " a, __func__, __LINE__, __VA_ARGS__)
#else
#define DPRINTF(a, ...) do { } while(0)
#endif

DECLARE_GLOBAL_DATA_PTR;

#ifndef CONFIG_SYS_DCACHE_OFF

/*
 *  With 4k page granule, a virtual address is split into 4 lookup parts
 *  spanning 9 bits each:
 *
 *    _______________________________________________
 *   |       |       |       |       |       |       |
 *   |   0   |  Lv0  |  Lv1  |  Lv2  |  Lv3  |  off  |
 *   |_______|_______|_______|_______|_______|_______|
 *     63-48   47-39   38-30   29-21   20-12   11-00
 *
 *             mask        page size
 *
 *    Lv0: FF8000000000       --
 *    Lv1:   7FC0000000       1G
 *    Lv2:     3FE00000       2M
 *    Lv3:       1FF000       4K
 *    off:          FFF
 */

#ifdef CONFIG_SYS_FULL_VA
static struct mm_region mem_map[] = CONFIG_SYS_MEM_MAP;

static u64 get_tcr(int el, u64 *pips, u64 *pva_bits)
{
	u64 max_addr = 0;
	u64 ips, va_bits;
	u64 tcr;
	int i;

	/* Find the largest address we need to support */
	for (i = 0; i < ARRAY_SIZE(mem_map); i++)
		max_addr = max(max_addr, mem_map[i].base + mem_map[i].size);

	/* Calculate the maximum physical (and thus virtual) address */
	if (max_addr > (1ULL << 44)) {
		ips = 5;
		va_bits = 48;
	} else  if (max_addr > (1ULL << 42)) {
		ips = 4;
		va_bits = 44;
	} else  if (max_addr > (1ULL << 40)) {
		ips = 3;
		va_bits = 42;
	} else  if (max_addr > (1ULL << 36)) {
		ips = 2;
		va_bits = 40;
	} else  if (max_addr > (1ULL << 32)) {
		ips = 1;
		va_bits = 36;
	} else {
		ips = 0;
		va_bits = 32;
	}

	if (el == 1) {
		tcr = TCR_EL1_RSVD | (ips << 32);
	} else if (el == 2) {
		tcr = TCR_EL2_RSVD | (ips << 16);
	} else {
		tcr = TCR_EL3_RSVD | (ips << 16);
	}

	/* PTWs cacheable, inner/outer WBWA and inner shareable */
	tcr |= TCR_TG0_4K | TCR_SHARED_INNER | TCR_ORGN_WBWA | TCR_IRGN_WBWA;
	tcr |= TCR_T0SZ(va_bits);

	if (pips)
		*pips = ips;
	if (pva_bits)
		*pva_bits = va_bits;

	return tcr;
}

#define MAX_PTE_ENTRIES 512

static int pte_type(u64 *pte)
{
	return *pte & PTE_TYPE_MASK;
}

/* Returns the LSB number for a PTE on level <level> */
static int level2shift(int level)
{
	/* Page is 12 bits wide, every level translates 9 bits */
	return (12 + 9 * (3 - level));
}

static u64 *find_pte(u64 addr, int level)
{
	int start_level = 0;
	u64 *pte;
	u64 idx;
	u64 va_bits;
	int i;

	DPRINTF("addr=%llx level=%d\n", addr, level);

	get_tcr(0, NULL, &va_bits);
	if (va_bits < 39)
		start_level = 1;

	if (level < start_level)
		return NULL;

	/* Walk through all page table levels to find our PTE */
	pte = (u64*)gd->arch.tlb_addr;
	for (i = start_level; i < 4; i++) {
		idx = (addr >> level2shift(i)) & 0x1FF;
		pte += idx;
		DPRINTF("idx=%llx PTE %p at level %d: %llx\n", idx, pte, i, *pte);

		/* Found it */
		if (i == level)
			return pte;
		/* PTE is no table (either invalid or block), can't traverse */
		if (pte_type(pte) != PTE_TYPE_TABLE)
			return NULL;
		/* Off to the next level */
		pte = (u64*)(*pte & 0x0000fffffffff000ULL);
	}

	/* Should never reach here */
	return NULL;
}

/* Creates a new full table (512 entries) and sets *pte to refer to it */
static u64 *create_table(void)
{
	u64 *new_table = (u64*)gd->arch.tlb_fillptr;
	u64 pt_len = MAX_PTE_ENTRIES * sizeof(u64);

	/* Allocate MAX_PTE_ENTRIES pte entries */
	gd->arch.tlb_fillptr += pt_len;

	if (gd->arch.tlb_fillptr - gd->arch.tlb_addr > gd->arch.tlb_size)
		panic("Insufficient RAM for page table: 0x%lx > 0x%lx",
			gd->arch.tlb_fillptr - gd->arch.tlb_addr,
			gd->arch.tlb_size);

	/* Mark all entries as invalid */
	memset(new_table, 0, pt_len);

	return new_table;
}

static void set_pte_table(u64 *pte, u64 *table)
{
	/* Point *pte to the new table */
	DPRINTF("Setting %p to addr=%p\n", pte, table);
	*pte = PTE_TYPE_TABLE | (ulong)table;
}

/* Add one mm_region map entry to the page tables */
static void add_map(struct mm_region *map)
{
	u64 *pte;
	u64 addr = map->base;
	u64 size = map->size;
	u64 attrs = map->attrs | PTE_TYPE_BLOCK | PTE_BLOCK_AF;
	u64 blocksize;
	int level;
	u64 *new_table;

	while (size) {
		pte = find_pte(addr, 0);
		if (pte && (pte_type(pte) == PTE_TYPE_FAULT)) {
			DPRINTF("Creating table for addr 0x%llx\n", addr);
			new_table = create_table();
			set_pte_table(pte, new_table);
		}

		for (level = 1; level < 4; level++) {
			pte = find_pte(addr, level);
			blocksize = 1ULL << level2shift(level);
			DPRINTF("Checking if pte fits for addr=%llx size=%llx "
				"blocksize=%llx\n", addr, size, blocksize);
			if (size >= blocksize && !(addr & (blocksize - 1))) {
				/* Page fits, create block PTE */
				DPRINTF("Setting PTE %p to block addr=%llx\n",
					pte, addr);
				*pte = addr | attrs;
				addr += blocksize;
				size -= blocksize;
				break;
			} else if ((pte_type(pte) == PTE_TYPE_FAULT)) {
				/* Page doesn't fit, create subpages */
				DPRINTF("Creating subtable for addr 0x%llx "
					"blksize=%llx\n", addr, blocksize);
				new_table = create_table();
				set_pte_table(pte, new_table);
			}
		}
	}
}

/* Splits a block PTE into table with subpages spanning the old block */
static void split_block(u64 *pte, int level)
{
	u64 old_pte = *pte;
	u64 *new_table;
	u64 i = 0;
	/* level describes the parent level, we need the child ones */
	int levelshift = level2shift(level + 1);

	if (pte_type(pte) != PTE_TYPE_BLOCK)
		panic("PTE %p (%llx) is not a block", pte, old_pte);

	new_table = create_table();
	DPRINTF("Splitting pte %p (%llx) into %p\n", pte, old_pte, new_table);

	for (i = 0; i < MAX_PTE_ENTRIES; i++) {
		new_table[i] = old_pte | (i << levelshift);
		DPRINTF("Setting new_table[%lld] = %llx\n", i, new_table[i]);
	}

	/* Set the new table into effect */
	set_pte_table(pte, new_table);
}

/* Returns the estimated required size of all page tables */
u64 get_page_table_size(void)
{
	int i;
	u64 one_pt = MAX_PTE_ENTRIES * sizeof(u64);
	u64 size = 0;

	/* root page table */
	size += one_pt;

	for (i = 0; i < ARRAY_SIZE(mem_map); i++) {
		struct mm_region *map = &mem_map[i];

		/* Account for Lv0 page tables */
		size += one_pt * ((map->size >> 39) + 1);

		/* 1GB aligned pages fit already, so count the others */
		if (map->size & 0x3fffffffULL)
			size += one_pt;
		if (map->base & 0x3fffffffULL)
			size += one_pt;
	}

	/* Assume we may have to split up to 4 more page tables off */
	size += one_pt * 4;

	return size;
}

static void setup_pgtables(void)
{
	int i;

	/*
	 * Allocate the first level we're on with invalidate entries.
	 * If the starting level is 0 (va_bits >= 39), then this is our
	 * Lv0 page table, otherwise it's the entry Lv1 page table.
	 */
	gd->arch.tlb_fillptr = gd->arch.tlb_addr;
	create_table();

	/* Now add all MMU table entries one after another to the table */
	for (i = 0; i < ARRAY_SIZE(mem_map); i++)
		add_map(&mem_map[i]);
}

#else

inline void set_pgtable_section(u64 *page_table, u64 index, u64 section,
			 u64 memory_type, u64 attribute)
{
	u64 value;

	value = section | PMD_TYPE_SECT | PMD_SECT_AF;
	value |= PMD_ATTRINDX(memory_type);
	value |= attribute;
	page_table[index] = value;
}

inline void set_pgtable_table(u64 *page_table, u64 index, u64 *table_addr)
{
	u64 value;

	value = (u64)table_addr | PMD_TYPE_TABLE;
	page_table[index] = value;
}
#endif

/* to activate the MMU we need to set up virtual memory */
__weak void mmu_setup(void)
{
#ifndef CONFIG_SYS_FULL_VA
	bd_t *bd = gd->bd;
	u64 *page_table = (u64 *)gd->arch.tlb_addr, i, j;
#endif
	int el;

#ifdef CONFIG_SYS_FULL_VA
	/* Set up page tables only once */
	if (!gd->arch.tlb_fillptr)
		setup_pgtables();

	el = current_el();
	set_ttbr_tcr_mair(el, gd->arch.tlb_addr, get_tcr(el, NULL, NULL),
			  MEMORY_ATTRIBUTES);
#else
	/* Setup an identity-mapping for all spaces */
	for (i = 0; i < (PGTABLE_SIZE >> 3); i++) {
		set_pgtable_section(page_table, i, i << SECTION_SHIFT,
				    MT_DEVICE_NGNRNE, PMD_SECT_NON_SHARE);
	}

	/* Setup an identity-mapping for all RAM space */
	for (i = 0; i < CONFIG_NR_DRAM_BANKS; i++) {
		ulong start = bd->bi_dram[i].start;
		ulong end = bd->bi_dram[i].start + bd->bi_dram[i].size;
		for (j = start >> SECTION_SHIFT;
		     j < end >> SECTION_SHIFT; j++) {
			set_pgtable_section(page_table, j, j << SECTION_SHIFT,
					    MT_NORMAL, PMD_SECT_NON_SHARE);
		}
	}

	/* load TTBR0 */
	el = current_el();
	if (el == 1) {
		set_ttbr_tcr_mair(el, gd->arch.tlb_addr,
				  TCR_EL1_RSVD | TCR_FLAGS | TCR_EL1_IPS_BITS,
				  MEMORY_ATTRIBUTES);
	} else if (el == 2) {
		set_ttbr_tcr_mair(el, gd->arch.tlb_addr,
				  TCR_EL2_RSVD | TCR_FLAGS | TCR_EL2_IPS_BITS,
				  MEMORY_ATTRIBUTES);
	} else {
		set_ttbr_tcr_mair(el, gd->arch.tlb_addr,
				  TCR_EL3_RSVD | TCR_FLAGS | TCR_EL3_IPS_BITS,
				  MEMORY_ATTRIBUTES);
	}
#endif

	/* enable the mmu */
	set_sctlr(get_sctlr() | CR_M);
}

/*
 * Performs a invalidation of the entire data cache at all levels
 */
void invalidate_dcache_all(void)
{
	__asm_invalidate_dcache_all();
}

/*
 * Performs a clean & invalidation of the entire data cache at all levels.
 * This function needs to be inline to avoid using stack.
 * __asm_flush_l3_cache return status of timeout
 */
inline void flush_dcache_all(void)
{
	int ret;

	__asm_flush_dcache_all();
	ret = __asm_flush_l3_cache();
	if (ret)
		debug("flushing dcache returns 0x%x\n", ret);
	else
		debug("flushing dcache successfully.\n");
}

/*
 * Invalidates range in all levels of D-cache/unified cache
 */
void invalidate_dcache_range(unsigned long start, unsigned long stop)
{
	__asm_flush_dcache_range(start, stop);
}

/*
 * Flush range(clean & invalidate) from all levels of D-cache/unified cache
 */
void flush_dcache_range(unsigned long start, unsigned long stop)
{
	__asm_flush_dcache_range(start, stop);
}

void dcache_enable(void)
{
	/* The data cache is not active unless the mmu is enabled */
	if (!(get_sctlr() & CR_M)) {
		invalidate_dcache_all();
		__asm_invalidate_tlb_all();
		mmu_setup();
	}

	set_sctlr(get_sctlr() | CR_C);
}

void dcache_disable(void)
{
	uint32_t sctlr;

	sctlr = get_sctlr();

	/* if cache isn't enabled no need to disable */
	if (!(sctlr & CR_C))
		return;

	set_sctlr(sctlr & ~(CR_C|CR_M));

	flush_dcache_all();
	__asm_invalidate_tlb_all();
}

int dcache_status(void)
{
	return (get_sctlr() & CR_C) != 0;
}

u64 *__weak arch_get_page_table(void) {
	puts("No page table offset defined\n");

	return NULL;
}

#ifndef CONFIG_SYS_FULL_VA
void mmu_set_region_dcache_behaviour(phys_addr_t start, size_t size,
				     enum dcache_option option)
{
	u64 *page_table = arch_get_page_table();
	u64 upto, end;

	if (page_table == NULL)
		return;

	end = ALIGN(start + size, (1 << MMU_SECTION_SHIFT)) >>
	      MMU_SECTION_SHIFT;
	start = start >> MMU_SECTION_SHIFT;
	for (upto = start; upto < end; upto++) {
		page_table[upto] &= ~PMD_ATTRINDX_MASK;
		page_table[upto] |= PMD_ATTRINDX(option);
	}
	asm volatile("dsb sy");
	__asm_invalidate_tlb_all();
	asm volatile("dsb sy");
	asm volatile("isb");
	start = start << MMU_SECTION_SHIFT;
	end = end << MMU_SECTION_SHIFT;
	flush_dcache_range(start, end);
	asm volatile("dsb sy");
}
#else
static bool is_aligned(u64 addr, u64 size, u64 align)
{
	return !(addr & (align - 1)) && !(size & (align - 1));
}

static u64 set_one_region(u64 start, u64 size, u64 attrs, int level)
{
	int levelshift = level2shift(level);
	u64 levelsize = 1ULL << levelshift;
	u64 *pte = find_pte(start, level);

	/* Can we can just modify the current level block PTE? */
	if (is_aligned(start, size, levelsize)) {
		*pte &= ~PMD_ATTRINDX_MASK;
		*pte |= attrs;
		DPRINTF("Set attrs=%llx pte=%p level=%d\n", attrs, pte, level);

		return levelsize;
	}

	/* Unaligned or doesn't fit, maybe split block into table */
	DPRINTF("addr=%llx level=%d pte=%p (%llx)\n", start, level, pte, *pte);

	/* Maybe we need to split the block into a table */
	if (pte_type(pte) == PTE_TYPE_BLOCK)
		split_block(pte, level);

	/* And then double-check it became a table or already is one */
	if (pte_type(pte) != PTE_TYPE_TABLE)
		panic("PTE %p (%llx) for addr=%llx should be a table",
		      pte, *pte, start);

	/* Roll on to the next page table level */
	return 0;
}

void mmu_set_region_dcache_behaviour(phys_addr_t start, size_t size,
				     enum dcache_option option)
{
	u64 attrs = PMD_ATTRINDX(option);
	u64 real_start = start;
	u64 real_size = size;

	DPRINTF("start=%lx size=%lx\n", (ulong)start, (ulong)size);

	/*
	 * Loop through the address range until we find a page granule that fits
	 * our alignment constraints, then set it to the new cache attributes
	 */
	while (size > 0) {
		int level;
		u64 r;

		for (level = 1; level < 4; level++) {
			r = set_one_region(start, size, attrs, level);
			if (r) {
				/* PTE successfully replaced */
				size -= r;
				start += r;
				break;
			}
		}

	}

	asm volatile("dsb sy");
	__asm_invalidate_tlb_all();
	asm volatile("dsb sy");
	asm volatile("isb");
	flush_dcache_range(real_start, real_start + real_size);
	asm volatile("dsb sy");
}
#endif

#else	/* CONFIG_SYS_DCACHE_OFF */

void invalidate_dcache_all(void)
{
}

void flush_dcache_all(void)
{
}

void dcache_enable(void)
{
}

void dcache_disable(void)
{
}

int dcache_status(void)
{
	return 0;
}

void mmu_set_region_dcache_behaviour(phys_addr_t start, size_t size,
				     enum dcache_option option)
{
}

#endif	/* CONFIG_SYS_DCACHE_OFF */

#ifndef CONFIG_SYS_ICACHE_OFF

void icache_enable(void)
{
	__asm_invalidate_icache_all();
	set_sctlr(get_sctlr() | CR_I);
}

void icache_disable(void)
{
	set_sctlr(get_sctlr() & ~CR_I);
}

int icache_status(void)
{
	return (get_sctlr() & CR_I) != 0;
}

void invalidate_icache_all(void)
{
	__asm_invalidate_icache_all();
}

#else	/* CONFIG_SYS_ICACHE_OFF */

void icache_enable(void)
{
}

void icache_disable(void)
{
}

int icache_status(void)
{
	return 0;
}

void invalidate_icache_all(void)
{
}

#endif	/* CONFIG_SYS_ICACHE_OFF */

/*
 * Enable dCache & iCache, whether cache is actually enabled
 * depend on CONFIG_SYS_DCACHE_OFF and CONFIG_SYS_ICACHE_OFF
 */
void __weak enable_caches(void)
{
	icache_enable();
	dcache_enable();
}
