/*
 *  EFI Human Interface Infrastructure ... interface
 *
 *  Copyright (c) 2017 Leif Lindholm
 *
 *  SPDX-License-Identifier:     GPL-2.0+
 */

#include <common.h>
#include <malloc.h>
#include <efi_loader.h>

const efi_guid_t efi_guid_hii_config_routing_protocol =
	EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID;
const efi_guid_t efi_guid_hii_database_protocol = EFI_HII_DATABASE_PROTOCOL_GUID;
const efi_guid_t efi_guid_hii_string_protocol = EFI_HII_STRING_PROTOCOL_GUID;

struct hii_package {
	// TODO should there be an associated efi_object?
	struct list_head string_tables;     /* list of string_table */
	/* we could also track fonts, images, etc */
};

struct string_table {
	struct list_head link;
	efi_string_id_t language_name;
	char *language;
	uint32_t nstrings;
	/* NOTE: string id starts at 1 so value is stbl->strings[id-1] */
	struct {
		efi_string_t string;
		/* we could also track font info, etc */
	} strings[];
};

static void free_strings_table(struct string_table *stbl)
{
	int i;

	for (i = 0; i < stbl->nstrings; i++)
		free(stbl->strings[i].string);
	free(stbl->language);
	free(stbl);
}

static struct hii_package *new_package(void)
{
	struct hii_package *hii = malloc(sizeof(*hii));
	INIT_LIST_HEAD(&hii->string_tables);
	return hii;
}

static void free_package(struct hii_package *hii)
{

	while (!list_empty(&hii->string_tables)) {
		struct string_table *stbl;

		stbl = list_first_entry(&hii->string_tables,
					struct string_table, link);
		list_del(&stbl->link);
		free_strings_table(stbl);
	}

	free(hii);
}

static efi_status_t add_strings_package(struct hii_package *hii,
	struct efi_hii_strings_package *strings_package)
{
	struct efi_hii_string_block *block;
	void *end = ((void *)strings_package) + strings_package->header.length;
	uint32_t nstrings = 0;
	unsigned id = 0;

	debug("header_size: %08x\n", strings_package->header_size);
	debug("string_info_offset: %08x\n", strings_package->string_info_offset);
	debug("language_name: %u\n", strings_package->language_name);
	debug("language: %s\n", strings_package->language);

	/* count # of string entries: */
	block = ((void *)strings_package) + strings_package->string_info_offset;
	while ((void *)block < end) {
		switch (block->block_type) {
		case EFI_HII_SIBT_STRING_UCS2: {
			struct efi_hii_sibt_string_ucs2_block *ucs2 =
				(void *)block;
			nstrings++;
			block = efi_hii_sibt_string_ucs2_block_next(ucs2);
			break;
		}
		case EFI_HII_SIBT_END:
			block = end;
			break;
		default:
			debug("unknown HII string block type: %02x\n",
			      block->block_type);
			return EFI_INVALID_PARAMETER;
		}
	}

	struct string_table *stbl = malloc(sizeof(*stbl) +
			(nstrings * sizeof(stbl->strings[0])));
	stbl->language_name = strings_package->language_name;
	stbl->language = strdup((char *)strings_package->language);
	stbl->nstrings = nstrings;

	list_add(&stbl->link, &hii->string_tables);

	/* and now parse string entries and populate string_table */
	block = ((void *)strings_package) + strings_package->string_info_offset;

	while ((void *)block < end) {
		switch (block->block_type) {
		case EFI_HII_SIBT_STRING_UCS2: {
			struct efi_hii_sibt_string_ucs2_block *ucs2 =
				(void *)block;
			int len = (u16_strlen(ucs2->string_text) + 1) * 2;

			debug("%4u: \"%ls\"\n", id + 1, ucs2->string_text);
			stbl->strings[id].string = malloc(len);
			memcpy(stbl->strings[id].string, ucs2->string_text, len);
			id++;
			block = efi_hii_sibt_string_ucs2_block_next(ucs2);
			break;
		}
		case EFI_HII_SIBT_END:
			return EFI_SUCCESS;
		default:
			debug("unknown HII string block type: %02x\n",
			      block->block_type);
			return EFI_INVALID_PARAMETER;
		}
	}

	return EFI_SUCCESS;
}

/*
 * EFI_HII_CONFIG_ROUTING_PROTOCOL
 */

static efi_status_t EFIAPI extract_config(
	const struct efi_hii_config_routing_protocol *this,
	const efi_string_t request,
	efi_string_t *progress,
	efi_string_t *results)
{
	EFI_ENTRY("%p, \"%ls\", %p, %p", this, request, progress, results);
	return EFI_EXIT(EFI_OUT_OF_RESOURCES);
}

static efi_status_t EFIAPI export_config(
	const struct efi_hii_config_routing_protocol *this,
	efi_string_t *results)
{
	EFI_ENTRY("%p, %p", this, results);
	return EFI_EXIT(EFI_OUT_OF_RESOURCES);
}

static efi_status_t EFIAPI route_config(
	const struct efi_hii_config_routing_protocol *this,
	const efi_string_t configuration,
	efi_string_t *progress)
{
	EFI_ENTRY("%p, \"%ls\", %p", this, configuration, progress);
	return EFI_EXIT(EFI_OUT_OF_RESOURCES);
}

static efi_status_t EFIAPI block_to_config(
	const struct efi_hii_config_routing_protocol *this,
	const efi_string_t config_request,
	const uint8_t *block,
	const efi_uintn_t block_size,
	efi_string_t *config,
	efi_string_t *progress)
{
	EFI_ENTRY("%p, \"%ls\", %p, %zu, %p, %p", this, config_request, block,
		  block_size, config, progress);
	return EFI_EXIT(EFI_OUT_OF_RESOURCES);
}

static efi_status_t EFIAPI config_to_block(
	const struct efi_hii_config_routing_protocol *this,
	const efi_string_t config_resp,
	const uint8_t *block,
	const efi_uintn_t *block_size,
	efi_string_t *progress)
{
	EFI_ENTRY("%p, \"%ls\", %p, %p, %p", this, config_resp, block,
		  block_size, progress);
	return EFI_EXIT(EFI_OUT_OF_RESOURCES);
}

static efi_status_t EFIAPI get_alt_config(
	const struct efi_hii_config_routing_protocol *this,
	const efi_string_t config_resp,
	const efi_guid_t *guid,
	const efi_string_t name,
	const struct efi_device_path *device_path,
	const efi_string_t alt_cfg_id,
	efi_string_t *alt_cfg_resp)
{
	EFI_ENTRY("%p, \"%ls\", %pUl, \"%ls\", %p, \"%ls\", %p", this,
		  config_resp, guid, name, device_path, alt_cfg_id,
		  alt_cfg_resp);
	return EFI_EXIT(EFI_OUT_OF_RESOURCES);
}


/*
 * EFI_HII_DATABASE_PROTOCOL
 */

static efi_status_t EFIAPI new_package_list(
	const struct efi_hii_database_protocol *this,
	const struct efi_hii_package_list_header *package_list,
	const efi_handle_t driver_handle,
	efi_hii_handle_t *handle)
{
	efi_status_t ret = EFI_SUCCESS;

	EFI_ENTRY("%p, %p, %p, %p", this, package_list, driver_handle, handle);

	if (!package_list || !driver_handle)
		return EFI_EXIT(EFI_INVALID_PARAMETER);

	struct hii_package *hii = new_package();
	struct efi_hii_package_header *package;
	void *end = ((void *)package_list) + package_list->package_length;

	debug("package_list: %pUl (%u)\n", &package_list->package_list_guid,
	      package_list->package_length);

	package = ((void *)package_list) + sizeof(*package_list);
	while ((void *)package < end) {
		debug("package=%p, package type=%x, length=%u\n", package,
		      package->type, package->length);
		switch (package->type) {
		case EFI_HII_PACKAGE_STRINGS:
			ret = add_strings_package(hii,
				(struct efi_hii_strings_package *)package);
			break;
		default:
			break;
		}

		if (ret != EFI_SUCCESS)
			goto error;

		package = ((void *)package) + package->length;
	}

	// TODO in theory there is some notifications that should be sent..

	*handle = hii;

	return EFI_EXIT(EFI_SUCCESS);

error:
	free_package(hii);
	return EFI_EXIT(ret);
}

static efi_status_t EFIAPI remove_package_list(
	const struct efi_hii_database_protocol *this,
	efi_hii_handle_t handle)
{
	struct hii_package *hii = handle;
	EFI_ENTRY("%p, %p", this, handle);
	free_package(hii);
	return EFI_EXIT(EFI_SUCCESS);
}

static efi_status_t EFIAPI update_package_list(
	const struct efi_hii_database_protocol *this,
	efi_hii_handle_t handle,
	const struct efi_hii_package_list_header *package_list)
{
	EFI_ENTRY("%p, %p, %p", this, handle, package_list);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI list_package_lists(
	const struct efi_hii_database_protocol *this,
	uint8_t package_type,
	const efi_guid_t *package_guid,
	efi_uintn_t *handle_buffer_length,
	efi_hii_handle_t *handle)
{
	EFI_ENTRY("%p, %u, %pUl, %p, %p", this, package_type, package_guid,
		  handle_buffer_length, handle);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI export_package_lists(
	const struct efi_hii_database_protocol *this,
	efi_hii_handle_t handle,
	efi_uintn_t *buffer_size,
	struct efi_hii_package_list_header *buffer)
{
	EFI_ENTRY("%p, %p, %p, %p", this, handle, buffer_size, buffer);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI register_package_notify(
	const struct efi_hii_database_protocol *this,
	uint8_t package_type,
	const efi_guid_t *package_guid,
	const void *package_notify_fn,
	efi_uintn_t notify_type,
	efi_handle_t *notify_handle)
{
	EFI_ENTRY("%p, %u, %pUl, %p, %zu, %p", this, package_type,
		  package_guid, package_notify_fn, notify_type,
		  notify_handle);
	return EFI_EXIT(EFI_OUT_OF_RESOURCES);
}

static efi_status_t EFIAPI unregister_package_notify(
	const struct efi_hii_database_protocol *this,
	efi_handle_t notification_handle)
{
	EFI_ENTRY("%p, %p", this, notification_handle);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI find_keyboard_layouts(
	const struct efi_hii_database_protocol *this,
	uint16_t *key_guid_buffer_length,
	efi_guid_t *key_guid_buffer)
{
	EFI_ENTRY("%p, %p, %p", this, key_guid_buffer_length, key_guid_buffer);
	return EFI_EXIT(EFI_NOT_FOUND); /* Invalid */
}

static efi_status_t EFIAPI get_keyboard_layout(
	const struct efi_hii_database_protocol *this,
	efi_guid_t *key_guid,
	uint16_t *keyboard_layout_length,
	struct efi_hii_keyboard_layout *keyboard_layout)
{
	EFI_ENTRY("%p, %pUl, %p, %p", this, key_guid, keyboard_layout_length,
		  keyboard_layout);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI set_keyboard_layout(
	const struct efi_hii_database_protocol *this,
	efi_guid_t *key_guid)
{
	EFI_ENTRY("%p, %pUl", this, key_guid);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI get_package_list_handle(
	const struct efi_hii_database_protocol *this,
	efi_hii_handle_t package_list_handle,
	efi_handle_t *driver_handle)
{
	EFI_ENTRY("%p, %p, %p", this, package_list_handle, driver_handle);
	return EFI_EXIT(EFI_INVALID_PARAMETER);
}


/*
 * EFI_HII_STRING_PROTOCOL
 */

static efi_status_t EFIAPI new_string(
	const struct efi_hii_string_protocol *this,
	efi_hii_handle_t package_list,
	efi_string_id_t *string_id,
	const uint8_t *language,
	const uint16_t *language_name,
	const efi_string_t string,
	const struct efi_font_info *string_font_info)
{
	EFI_ENTRY("%p, %p, %p, \"%s\", %p, \"%ls\", %p", this, package_list,
		  string_id, language, language_name, string,
		  string_font_info);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI get_string(
	const struct efi_hii_string_protocol *this,
	const uint8_t *language,
	efi_hii_handle_t package_list,
	efi_string_id_t string_id,
	efi_string_t string,
	efi_uintn_t *string_size,
	struct efi_font_info **string_font_info)
{
	struct hii_package *hii = package_list;
	struct string_table *stbl;

	EFI_ENTRY("%p, \"%s\", %p, %u, %p, %p, %p", this, language,
		  package_list, string_id, string, string_size,
		  string_font_info);

	list_for_each_entry(stbl, &hii->string_tables, link) {
		if (!strcmp((char *)language, (char *)stbl->language)) {
			unsigned idx = string_id - 1;
			if (idx > stbl->nstrings)
				return EFI_EXIT(EFI_NOT_FOUND);
			efi_string_t str = stbl->strings[idx].string;
			size_t len = u16_strlen(str) + 1;
			if (*string_size < len * 2) {
				*string_size = len * 2;
				return EFI_EXIT(EFI_BUFFER_TOO_SMALL);
			}
			memcpy(string, str, len * 2);
			*string_size = len * 2;
			return EFI_EXIT(EFI_SUCCESS);
		}
	}

	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI set_string(
	const struct efi_hii_string_protocol *this,
	efi_hii_handle_t package_list,
	efi_string_id_t string_id,
	const uint8_t *language,
	const efi_string_t string,
	const struct efi_font_info *string_font_info)
{
	EFI_ENTRY("%p, %p, %u, \"%s\", \"%ls\", %p", this, package_list,
		  string_id, language, string, string_font_info);
	return EFI_EXIT(EFI_NOT_FOUND);
}

static efi_status_t EFIAPI get_languages(
	const struct efi_hii_string_protocol *this,
	efi_hii_handle_t package_list,
	uint8_t *languages,
	efi_uintn_t *languages_size)
{
	struct hii_package *hii = package_list;
	struct string_table *stbl;
	size_t len = 0;

	EFI_ENTRY("%p, %p, %p, %p", this, package_list, languages,
		  languages_size);

	/* figure out required size: */
	list_for_each_entry(stbl, &hii->string_tables, link) {
		len += strlen((char *)stbl->language) + 1;
	}

	if (*languages_size < len) {
		*languages_size = len;
		return EFI_EXIT(EFI_BUFFER_TOO_SMALL);
	}

	char *p = (char *)languages;
	list_for_each_entry(stbl, &hii->string_tables, link) {
		if (p != (char *)languages)
			p += sprintf(p, ";");
		p += sprintf(p, "%s", stbl->language);
	}

	debug("languages: %s\n", languages);

	return EFI_EXIT(EFI_SUCCESS);
}

static efi_status_t EFIAPI get_secondary_languages(
	const struct efi_hii_string_protocol *this,
	efi_hii_handle_t package_list,
	const uint8_t *primary_language,
	uint8_t *secondary_languages,
	efi_uintn_t *secondary_languages_size)
{
	EFI_ENTRY("%p, %p, \"%s\", %p, %p", this, package_list,
		  primary_language, secondary_languages,
		  secondary_languages_size);
	return EFI_EXIT(EFI_NOT_FOUND);
}

const struct efi_hii_config_routing_protocol efi_hii_config_routing = {
	.extract_config = extract_config,
	.export_config = export_config,
	.route_config = route_config,
	.block_to_config = block_to_config,
	.config_to_block = config_to_block,
	.get_alt_config = get_alt_config
};
const struct efi_hii_database_protocol efi_hii_database = {
	.new_package_list = new_package_list,
	.remove_package_list = remove_package_list,
	.update_package_list = update_package_list,
	.list_package_lists = list_package_lists,
	.export_package_lists = export_package_lists,
	.register_package_notify = register_package_notify,
	.unregister_package_notify = unregister_package_notify,
	.find_keyboard_layouts = find_keyboard_layouts,
	.get_keyboard_layout = get_keyboard_layout,
	.set_keyboard_layout = set_keyboard_layout,
	.get_package_list_handle = get_package_list_handle
};
const struct efi_hii_string_protocol efi_hii_string = {
	.new_string = new_string,
	.get_string = get_string,
	.set_string = set_string,
	.get_languages = get_languages,
	.get_secondary_languages = get_secondary_languages
};
