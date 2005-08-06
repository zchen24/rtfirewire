/**
 * @ingroup configrom
 * @file
 *
 * data structure and interfaces of configrom module
 */


#ifndef _IEEE1394_CONFIG_ROMS_H
#define _IEEE1394_CONFIG_ROMS_H

#include "ieee1394_types.h"
#include "hosts.h"

/**
 * @ingroup configrom
 * @struct hpsb_config_rom_entry
 */
 struct hpsb_config_rom_entry {
	const char *name;

	/* Base initialization, called at module load */
	int (*init)(void);

	/* Add entry to specified host */
	int (*add)(struct hpsb_host *host);

	/* Remove entry from specified host */
	void (*remove)(struct hpsb_host *host);

	/* Cleanup called at module exit */
	void (*cleanup)(void);

	/* The flag added to host->config_roms */
	unsigned int flag;
};

/* The default host entry. This must succeed. */
int hpsb_default_host_entry(struct hpsb_host *host);

/* Initialize all config roms */
int hpsb_init_config_roms(void);

/* Cleanup all config roms */
void hpsb_cleanup_config_roms(void);

/* Add extra config roms to specified host */
int hpsb_add_extra_config_roms(struct hpsb_host *host);

/* Remove extra config roms from specified host */
void hpsb_remove_extra_config_roms(struct hpsb_host *host);


/* List of flags to check if a host contains a certain extra config rom
 * entry. Available in the host->config_roms member. */
#define HPSB_CONFIG_ROM_ENTRY_IP1394		0x00000001

#endif /* _IEEE1394_CONFIG_ROMS_H */
