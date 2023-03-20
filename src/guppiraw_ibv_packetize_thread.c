// guppiraw_ibv_packetize_thread
//
// Ingest the GUPPI-RAW files with stem as per `RAWSTEM` key-value,
// generate packet-payloads emulating that of the ibverbs_packet_thread,
// and pass that buffer along. 
//
// Particularly used for offline testing, where a GUPPI-RAW file provides
// packet data.

#define _GNU_SOURCE 1
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>

#include "hashpipe.h"
#include "hpguppi_databuf.h"
#include "hpguppi_time.h"
#include "hpguppi_atasnap.h"
#include "hpguppi_util.h"
#include "hpguppi_pktbuf.h"
#include "guppirawc99.h"

typedef struct {
  uint32_t guppi_blocsize;
  uint32_t pktnchan, pktntime;
  uint32_t blockn_ant, blockn_freq, blockn_pol;
  uint32_t nbits;
  uint32_t schan;
  
  uint64_t pktidx, pktstart, pktstop;

  double obsfreq;
  double obsbw;
  double tbin;

} guppiraw_block_meta_t;

const uint64_t KEY_UINT64_BLOCSIZE = GUPPI_RAW_KEY_UINT64_ID_LE('B','L','O','C','S','I','Z','E');
const uint64_t KEY_UINT64_PKTNCHAN = GUPPI_RAW_KEY_UINT64_ID_LE('P','K','T','N','C','H','A','N');
const uint64_t KEY_UINT64_PKTNTIME = GUPPI_RAW_KEY_UINT64_ID_LE('P','K','T','N','T','I','M','E');
const uint64_t KEY_UINT64_NANTS    = GUPPI_RAW_KEY_UINT64_ID_LE('N','A','N','T','S',' ',' ',' ');
const uint64_t KEY_UINT64_OBSNCHAN = GUPPI_RAW_KEY_UINT64_ID_LE('O','B','S','N','C','H','A','N');
const uint64_t KEY_UINT64_NPOL     = GUPPI_RAW_KEY_UINT64_ID_LE('N','P','O','L',' ',' ',' ',' ');
const uint64_t KEY_UINT64_NBITS    = GUPPI_RAW_KEY_UINT64_ID_LE('N','B','I','T','S',' ',' ',' ');
const uint64_t KEY_UINT64_SCHAN    = GUPPI_RAW_KEY_UINT64_ID_LE('S','C','H','A','N',' ',' ',' ');
const uint64_t KEY_UINT64_PKTIDX   = GUPPI_RAW_KEY_UINT64_ID_LE('P','K','T','I','D','X',' ',' ');
const uint64_t KEY_UINT64_PKTSTART = GUPPI_RAW_KEY_UINT64_ID_LE('P','K','T','S','T','A','R','T');
const uint64_t KEY_UINT64_PKTSTOP  = GUPPI_RAW_KEY_UINT64_ID_LE('P','K','T','S','T','O','P',' ');
const uint64_t KEY_UINT64_OBSFREQ  = GUPPI_RAW_KEY_UINT64_ID_LE('O','B','S','F','R','E','Q',' ');
const uint64_t KEY_UINT64_OBSBW    = GUPPI_RAW_KEY_UINT64_ID_LE('O','B','S','B','W',' ',' ',' ');
const uint64_t KEY_UINT64_TBIN     = GUPPI_RAW_KEY_UINT64_ID_LE('T','B','I','N',' ',' ',' ',' ');

void guppiraw_parse_block_meta(const char* entry, void* block_meta) {
  if(((uint64_t*)entry)[0] == KEY_UINT64_BLOCSIZE) {
    hgetu4(entry, "BLOCSIZE", &((guppiraw_block_meta_t*)block_meta)->guppi_blocsize);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_PKTNCHAN) {
    hgetu4(entry, "PKTNCHAN", &((guppiraw_block_meta_t*)block_meta)->pktnchan);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_PKTNTIME) {
    hgetu4(entry, "PKTNTIME", &((guppiraw_block_meta_t*)block_meta)->pktntime);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_NANTS) {
    hgetu4(entry, "NANTS", &((guppiraw_block_meta_t*)block_meta)->blockn_ant);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_OBSNCHAN) {
    hgetu4(entry, "OBSNCHAN", &((guppiraw_block_meta_t*)block_meta)->blockn_freq);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_NPOL) {
    hgetu4(entry, "NPOL", &((guppiraw_block_meta_t*)block_meta)->blockn_pol);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_NBITS) {
    hgetu4(entry, "NBITS", &((guppiraw_block_meta_t*)block_meta)->nbits);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_SCHAN) {
    hgetu4(entry, "SCHAN", &((guppiraw_block_meta_t*)block_meta)->schan);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_PKTIDX) {
    hgetu8(entry, "PKTIDX", &((guppiraw_block_meta_t*)block_meta)->pktidx);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_PKTSTART) {
    hgetu8(entry, "PKTSTART", &((guppiraw_block_meta_t*)block_meta)->pktstart);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_PKTSTOP) {
    hgetu8(entry, "PKTSTOP", &((guppiraw_block_meta_t*)block_meta)->pktstop);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_OBSFREQ) {
    hgetr8(entry, "OBSFREQ", &((guppiraw_block_meta_t*)block_meta)->obsfreq);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_OBSBW) {
    hgetr8(entry, "OBSBW", &((guppiraw_block_meta_t*)block_meta)->obsbw);
  }
  else if(((uint64_t*)entry)[0] == KEY_UINT64_TBIN) {
    hgetr8(entry, "TBIN", &((guppiraw_block_meta_t*)block_meta)->tbin);
  }
  else if(guppiraw_header_entry_is_END((uint64_t*)entry)) {
    if(&((guppiraw_block_meta_t*)block_meta)->blockn_ant == 0) {
      ((guppiraw_block_meta_t*)block_meta)->blockn_ant = 1;
    }
  }
}

// Parses the ibvpktsz string for chunk sizes and initializes db's pktbuf_info
// accordingly.  Returns 0 on success or -1 on error.
static
int
parse_ibvpktsz(struct hpguppi_pktbuf_info *pktbuf_info, char * ibvpktsz, size_t blocksize)
{
  int i;
  char * p;
  uint32_t nchunks = 0;
  size_t pkt_size = 0;
  size_t slot_size = 0;

  if(!ibvpktsz) {
    return -1;
  }

  // Look for commas
  while(nchunks < MAX_CHUNKS && (p = strchr(ibvpktsz, ','))) {
    // Replace comma with nul
    *p = '\0';
    // Parse chuck size
    pktbuf_info->chunks[nchunks].chunk_size = strtoul(ibvpktsz, NULL, 0);
    // Replace nul with comma
    *p = ',';
    // If chunk_size is 0, return error
    if(pktbuf_info->chunks[nchunks].chunk_size == 0) {
      hashpipe_error("IBVPKTSZ", "chunk size must be non-zero");
      return -1;
    }
    // Increment nchunks
    nchunks++;
    // Advance ibvpktsz to character beyond p
    ibvpktsz = p+1;
  }

  // If nchunks is less than MAX_CHUNKS and ibvpktsz[0] is not nul
  if(nchunks < MAX_CHUNKS && *ibvpktsz) {
    // If more commas remain, too many chunks!
    if(strchr(ibvpktsz, ',')) {
      hashpipe_error("IBVPKTSZ", "too many chunks");
      return -1;
    }
    // Parse final chunk size
    pktbuf_info->chunks[nchunks].chunk_size = strtoul(ibvpktsz, NULL, 0);
    // Increment nchunks
    nchunks++;
  } else if(nchunks == MAX_CHUNKS && *ibvpktsz) {
    // Too many chunks
    hashpipe_error("IBVPKTSZ", "too many chunks");
    return -1;
  }

  // Calculate remaining fields
  for(i=0; i<nchunks; i++) {
    pktbuf_info->chunks[i].chunk_aligned_size = pktbuf_info->chunks[i].chunk_size +
      ((-pktbuf_info->chunks[i].chunk_size) % PKT_ALIGNMENT_SIZE);
    pktbuf_info->chunks[i].chunk_offset = slot_size;
    // Accumulate pkt_size and slot_size
    pkt_size += pktbuf_info->chunks[i].chunk_size;
    slot_size += pktbuf_info->chunks[i].chunk_aligned_size;
  }

  // Store final values
  pktbuf_info->num_chunks = nchunks;
  pktbuf_info->pkt_size = pkt_size;
  pktbuf_info->slot_size = slot_size;
  pktbuf_info->slots_per_block = blocksize / slot_size;

  pktbuf_info->slots_per_block = (pktbuf_info->slots_per_block/8) * 8;

  return 0;
}

static int init(hashpipe_thread_args_t *args)
{
  // Local aliases to shorten access to args fields
  // Our output buffer happens to be a hpguppi_input_databuf
  hpguppi_input_databuf_t *db = (hpguppi_input_databuf_t *)args->obuf;
  hashpipe_status_t * st = &args->st;
  const char * status_key = args->thread_desc->skey;
  const char * thread_name = args->thread_desc->name;

  char guppifile_pathstem[73] = {'\0'};
  char guppifile_path[sizeof(guppifile_pathstem)+10] = {'\0'};

  uint32_t blocsize=0;
  char ibvpktsz[80];
  strcpy(ibvpktsz, "42,16,8192");

  hashpipe_status_lock_safe(st);
    hgets(st->buf, "RAWSTEM", sizeof(guppifile_pathstem), guppifile_pathstem);
  hashpipe_status_unlock_safe(st);
  sprintf(guppifile_path, "%s.0000.raw", guppifile_pathstem);
  
  guppiraw_iterate_info_t gr_iterate = {0};
  if(guppiraw_iterate_open_with_user_metadata(&gr_iterate, guppifile_path, sizeof(guppiraw_block_meta_t), guppiraw_parse_block_meta)) {
    hashpipe_error(thread_name, "Failed to open `RAWSTEM` specified %s.", guppifile_path);
    return HASHPIPE_ERR_PARAM;
  }

  hashpipe_info(thread_name, "Opened %s.", guppifile_path);
  guppiraw_block_meta_t* guppiblock_metadata = (guppiraw_block_meta_t*)guppiraw_iterate_metadata(&gr_iterate)->user_data;

  hashpipe_info(thread_name, "Block parameters:");
  hashpipe_info(thread_name, "\tBLOCSIZE = %d", guppiblock_metadata->guppi_blocsize);
  hashpipe_info(thread_name, "\tPKTNCHAN = %d", guppiblock_metadata->pktnchan);
  hashpipe_info(thread_name, "\tPKTNTIME = %d", guppiblock_metadata->pktntime);
  hashpipe_info(thread_name, "\tNANTS    = %d", guppiblock_metadata->blockn_ant);
  hashpipe_info(thread_name, "\tOBSNCHAN = %d", guppiblock_metadata->blockn_freq);
  hashpipe_info(thread_name, "\tNPOL     = %d", guppiblock_metadata->blockn_pol);
  hashpipe_info(thread_name, "\tNBITS    = %d", guppiblock_metadata->nbits);
  hashpipe_info(thread_name, "\tSCHAN    = %d", guppiblock_metadata->schan);

  // set BLOCSIZE to the next lowest multiple of the RAW input BLOCSIZE
  int blocksize_ratio = (hpguppi_databuf_size(db)/guppiblock_metadata->guppi_blocsize);
  hashpipe_info(thread_name, "File blocksize: %d, Pipeline blocksize %d, Ratio (O/I): %d", hpguppi_databuf_size(db), guppiblock_metadata->guppi_blocsize, blocksize_ratio);
  // further restrict blocsize so that it is at most 1/4 the entire ingest file
  // 1/4 ensures 4 blocks are pushed downstream before the file completes. This
  // is sure to trigger the payload_order_thread to push at least one of its
  // n_wblock=3 working blocks further downstream, securing the inititialisation of the 
  // 'observation' and an output file.
  if(blocksize_ratio > 4) {
    blocksize_ratio = 4;
    hashpipe_warn(thread_name, "Reduced blocksize ratio (O/I): %d", blocksize_ratio);
  }
  blocsize = blocksize_ratio*guppiblock_metadata->guppi_blocsize;

  hashpipe_status_lock_safe(st);
  {
    // get keys that can override those values of the GUPPIRAW header
    hgetu4(st->buf, "PKTNCHAN", &guppiblock_metadata->pktnchan);
    hgetu4(st->buf, "PKTNTIME", &guppiblock_metadata->pktntime);

    // push keys
    hputu4(st->buf, "BLOCSIZE", blocsize);
    hputu4(st->buf, "RAWBLKSZ", guppiblock_metadata->guppi_blocsize);
    hputu4(st->buf, "PKTNCHAN", guppiblock_metadata->pktnchan);
    hputu4(st->buf, "PKTNTIME", guppiblock_metadata->pktntime);
    hputu4(st->buf, "NANTS", guppiblock_metadata->blockn_ant);
    hputu4(st->buf, "OBSNCHAN", guppiblock_metadata->blockn_freq);
    hputu4(st->buf, "NPOL", guppiblock_metadata->blockn_pol);
    hputu4(st->buf, "NBITS", guppiblock_metadata->nbits);
    hputu4(st->buf, "SCHAN", guppiblock_metadata->schan);

    hgets(st->buf, "IBVPKTSZ", sizeof(ibvpktsz), ibvpktsz);
    hputs(st->buf, "IBVPKTSZ", ibvpktsz);

    // Set status_key to init
    hputs(st->buf, status_key, "init");
  }
  hashpipe_status_unlock_safe(st);

  // Get pointer to hpguppi_pktbuf_info
  struct hpguppi_pktbuf_info * pktbuf_info = hpguppi_pktbuf_info_ptr(db);
  if(parse_ibvpktsz(pktbuf_info, ibvpktsz, blocsize)) {
    return HASHPIPE_ERR_PARAM;
  }
  
  if(pktbuf_info->chunks[2].chunk_size < (guppiblock_metadata->pktnchan*guppiblock_metadata->pktntime*guppiblock_metadata->blockn_pol*2*guppiblock_metadata->nbits)/8) {
    hashpipe_error(
      thread_name,
      "pktbuf_info->chunks[2].chunk_size (%d) < (%d*%d*%d*2*%d/8) pktnchan*pktntime*npol*nbits/8",
      pktbuf_info->chunks[2].chunk_size, guppiblock_metadata->pktnchan, guppiblock_metadata->pktntime, guppiblock_metadata->blockn_pol, guppiblock_metadata->nbits
    );
    return HASHPIPE_ERR_PARAM;
  }

  // Success!
  return HASHPIPE_OK;
}

static void * run(hashpipe_thread_args_t * args)
{
  // Local aliases to shorten access to args fields
  // Our input and output buffers happen to be a hpguppi_input_databuf
  struct hpguppi_input_databuf *dbout = (struct hpguppi_input_databuf *)args->obuf;
  hashpipe_status_t *st = &args->st;
  const char * thread_name = args->thread_desc->name;
  // const char * status_key = args->thread_desc->skey;

  /* administrative variables */  
  // Get pointer to hpguppi_pktbuf_info, setup in init
  size_t blockpkt_slot = 0;
  struct hpguppi_pktbuf_info * pktbuf_info = hpguppi_pktbuf_info_ptr(dbout);
  const struct hpguppi_pktbuf_chunk * chunks = pktbuf_info->chunks;
  const size_t slots_per_block = pktbuf_info->slots_per_block;
  uint32_t pktnchan=-1, pktntime=-1;
  
  uint32_t blockn_ant, blockn_freq, blockn_time, blockn_pol;
  uint16_t blockant_i=0, blockfreq_i=0, blocktime_i=0, blockpol_i=0;
  uint64_t pktidx=0;
  uint32_t schan=0;
  uint32_t blocsize=0;
  uint32_t nbits=0;

  struct ata_snap_payload_header pkt_header = {0};
  pkt_header.version = 42;
  pkt_header.type = 42;

  uint8_t* base_addr;
  char curblk = 0;//, rv;

  /* guppifile variables */
  char guppifile_pathstem[73] = {'\0'};
  char guppifile_path[sizeof(guppifile_pathstem)+10] = {'\0'};
  int guppifile_i = 0;
  off_t guppifile_pos;
  int guppifile_fd;

  /* start up */
  hashpipe_status_lock_safe(st);
    hgets(st->buf, "RAWSTEM", sizeof(guppifile_pathstem), guppifile_pathstem);
  
    hgetu4(st->buf, "RAWBLKSZ", &blocsize);
    hgetu4(st->buf, "PKTNCHAN", &pktnchan);
    hgetu4(st->buf, "PKTNTIME", &pktntime);
    blockn_ant = 1; // default
    hgetu4(st->buf, "NANTS", &blockn_ant);
    hgetu4(st->buf, "OBSNCHAN", &blockn_freq);
    hgetu4(st->buf, "NPOL", &blockn_pol);
    hgetu4(st->buf, "NBITS", &nbits);
    hgetu4(st->buf, "SCHAN", &schan);
  hashpipe_status_unlock_safe(st);
  blockn_freq /= blockn_ant;
  
  if(chunks[2].chunk_size != (pktnchan*pktntime*blockn_pol*2*nbits)/8) {
    hashpipe_warn(
      thread_name,
      "Excessive pktpayload_bytesize is suboptimal: (%d) != (%d = %d*%d*%d*2*%d/8) pktnchan*pktntime*npol*nbits/8",
        chunks[2].chunk_size,
        (pktnchan*pktntime*blockn_pol*2*nbits)/8,
        pktnchan,
        pktntime,
        blockn_pol,
        nbits
    );
  }

  blockn_time = blocsize / ((blockn_ant * blockn_freq * blockn_pol * 2 * nbits)/8);
  hashpipe_info(thread_name, "NTIME: %d", blockn_time);

  if(blockn_time % pktntime != 0) {
    hashpipe_error(thread_name, "NTIME (%d) %% (%d) PKTNTIME != 0", blockn_time, pktntime);
    pthread_exit(NULL);
    return NULL;
  }

  if(blockn_freq % pktnchan != 0) {
    hashpipe_error(thread_name, "NCHAN (%d) %% (%d) PKTNCHAN != 0", blockn_freq, pktntime);
    pthread_exit(NULL);
    return NULL;
  }

  // GUPPI RAW data-block is (slowest)[NANT, FREQ, TIME, POL, complex-sample](fastest)
  // RTR
  const size_t blocktime_stride = (blockn_pol * 2 * nbits)/8;
  const size_t atomic_slice = pktntime * blocktime_stride;
  const size_t blockfreq_stride = blockn_time * blocktime_stride;
  const size_t blockant_stride = blockn_freq * blockfreq_stride;

  while(hpguppi_databuf_wait_free(dbout, curblk) == HASHPIPE_TIMEOUT && run_threads());

  sprintf(guppifile_path, "%s.%04d.raw", guppifile_pathstem, guppifile_i%10000);
  guppifile_fd = open(guppifile_path, O_RDONLY);

  guppiraw_block_info_t gr_blockinfo = {0};
  guppiraw_metadata_t* metadata = &gr_blockinfo.metadata;
  metadata->user_data = malloc(sizeof(guppiraw_block_meta_t));
  memset(metadata->user_data, 0, sizeof(guppiraw_block_meta_t));
  metadata->user_callback = guppiraw_parse_block_meta;
  guppiraw_block_meta_t* guppiblock_metadata = metadata->user_data;

  while(guppifile_fd != -1) {
    hashpipe_info(thread_name, "Opened %s.", guppifile_path);

    if(guppifile_i == 0) {
      // read critical keys from GUPPIRAW header and push to status buffer
      guppiraw_read_blockheader(guppifile_fd, &gr_blockinfo);
      hashpipe_info(thread_name, "PKTSTOP: %llu", guppiblock_metadata->pktstop);

      hashpipe_status_lock_safe(st);
        hputu8(st->buf, "PKTSTART", guppiblock_metadata->pktstart);
        hputu8(st->buf, "PKTSTOP", guppiblock_metadata->pktstop);
        hputs(st->buf,  "IBVSTAT", "running"); // spoof
      hashpipe_status_unlock_safe(st);
    }

    while(guppiraw_read_blockheader(guppifile_fd, &gr_blockinfo) == 0) {
      // fprintf(stderr, "Block parameters:\n");
      // fprintf(stderr, "\tBLOCSIZE = %lu\n", guppiblock_metadata->guppi_blocsize);
      // fprintf(stderr, "\tOBSNCHAN = %d\n",  guppiblock_metadata->blockn_freq);
      // fprintf(stderr, "\tNANTS    = %d\n",  guppiblock_metadata->blockn_ants);
      // fprintf(stderr, "\tNBITS    = %d\n",  guppiblock_metadata->nbits);
      // fprintf(stderr, "\tNPOL     = %d\n",  guppiblock_metadata->blockn_pol);
      // fprintf(stderr, "\tOBSFREQ  = %g\n",  guppiblock_metadata->obsfreq);
      // fprintf(stderr, "\tOBSBW    = %g\n",  guppiblock_metadata->obsbw);
      // fprintf(stderr, "\tTBIN     = %g\n",  guppiblock_metadata->tbin);
      
      if(blocsize != guppiblock_metadata->guppi_blocsize) {
        hashpipe_error(thread_name, "BLOCSIZE changed during observation from %llu to %llu.", blocsize, guppiblock_metadata->guppi_blocsize);
        guppifile_i = -2; // break file progression
        break;
      }
      if(pktidx != guppiblock_metadata->pktidx) {
        hashpipe_warn(thread_name, "PKTIDX %llu is not the expected %llu.", guppiblock_metadata->pktidx, pktidx);
      }
      
      // store block-data start
      guppifile_pos = lseek(guppifile_fd, 0, SEEK_CUR);
      do {
        base_addr = hpguppi_pktbuf_block_slot_ptr(dbout, curblk, blockpkt_slot);
        pkt_header.timestamp = __bswap_64(pktidx);
        pkt_header.chan = __bswap_16(schan + blockfreq_i);
        pkt_header.feng_id = __bswap_16(blockant_i);
        
        // assume first chunk is ethernet head
        // memcpy(base_addr + chunks[0].chunk_offset, &, chunks[0].chunk_size);
        // assume second chunk is packet header
        memcpy(base_addr + chunks[1].chunk_offset, &pkt_header, chunks[1].chunk_size);
        // assume third chunk is packet payload
        // have to stride frequency dimension to write PKTNCHAN into payload
        for(int chan_off = 0; chan_off <= pktnchan; chan_off++){
          lseek(
            guppifile_fd,
            guppifile_pos + (
              blocktime_i*blocktime_stride +
              (blockfreq_i + chan_off)*blockfreq_stride +
              blockant_i*blockant_stride
            ),
            SEEK_SET
          );
          read(
            guppifile_fd,
            base_addr + chunks[2].chunk_offset + chan_off*atomic_slice,
            atomic_slice
          );
        }

        // increment indices
        blockpkt_slot = (blockpkt_slot + 1)%slots_per_block;
        if(blockpkt_slot == 0){
          //! TODO update status while waiting
          hashpipe_status_lock_safe(st);
            memcpy((char*)hpguppi_databuf_header(dbout, curblk), st->buf, HASHPIPE_STATUS_TOTAL_SIZE);
          hashpipe_status_unlock_safe(st);

          hpguppi_databuf_set_filled(dbout, curblk);
          curblk = (curblk + 1) %dbout->header.n_block;
          // progress buffers
          while(hpguppi_databuf_wait_free(dbout, curblk) == HASHPIPE_TIMEOUT && run_threads());
        }

        // Iterate through dimensions
        blockant_i = (blockant_i + 1) % blockn_ant;
        if (blockant_i == 0) {
          blockfreq_i = (blockfreq_i + pktnchan) % blockn_freq;
          if (blockfreq_i == 0) {
            blocktime_i = (blocktime_i + pktntime) % blockn_time;
            blockpol_i = (blockpol_i + blockn_pol) % blockn_pol; // practically no-op
            pktidx += pktntime;
          }
        }
      } while ((blockant_i | blockfreq_i | blocktime_i | blockpol_i) != 0);
      if(metadata->directio) {
        blocsize = ((blocsize+511)/512) * 512;
      }
      lseek(guppifile_fd, guppifile_pos+blocsize, SEEK_SET);
    } // while read_header (for each block)

    close(guppifile_fd);
    if(++guppifile_i == 10000){
      break;
    }
    sprintf(guppifile_path, "%s.%04d.raw", guppifile_pathstem, guppifile_i%10000);
    guppifile_fd = open(guppifile_path, O_RDONLY);
  } // while guppifile_fd
  hashpipe_info(thread_name, "Could not open %s.", guppifile_path);

  int obsdone;
  hget_obsdone(st, &obsdone);
  while(!obsdone){
    do {
      base_addr = hpguppi_pktbuf_block_slot_ptr(dbout, curblk, blockpkt_slot);
      pkt_header.timestamp = __bswap_64(pktidx);
      pkt_header.chan = __bswap_16(schan + blockfreq_i);
      pkt_header.feng_id = __bswap_16(blockant_i);

      // assume second chunk is packet header
      memcpy(base_addr + chunks[1].chunk_offset, &pkt_header, chunks[1].chunk_size);
      // don't bother with data

      // increment indices
      blockpkt_slot = (blockpkt_slot + 1)%slots_per_block;
      if(blockpkt_slot == 0){
        hashpipe_status_lock_safe(st);
          memcpy((char*)hpguppi_databuf_header(dbout, curblk), st->buf, HASHPIPE_STATUS_TOTAL_SIZE);
        hashpipe_status_unlock_safe(st);

        hpguppi_databuf_set_filled(dbout, curblk);
        curblk = (curblk + 1) %dbout->header.n_block;
        // progress buffers
        while(hpguppi_databuf_wait_free(dbout, curblk) == HASHPIPE_TIMEOUT && run_threads());
      }

      // Iterate through dimensions
      blockant_i = (blockant_i + 1) % blockn_ant;
      if (blockant_i == 0) {
        blockfreq_i = (blockfreq_i + pktnchan) % blockn_freq;
        if (blockfreq_i == 0) {
          blocktime_i = (blocktime_i + pktntime) % blockn_time;
          blockpol_i = (blockpol_i + blockn_pol) % blockn_pol; // practically no-op
          pktidx += pktntime;
        }
      }
    } while ((blockant_i | blockfreq_i | blocktime_i | blockpol_i) != 0);
    hget_obsdone(st, &obsdone);
  }

  hashpipe_info(thread_name, "exiting!");
  pthread_exit(NULL);

  return NULL;
}

static hashpipe_thread_desc_t thread_desc = {
    name: "guppiraw_ibv_packetize_thread",
    skey: "SYNSTAT",
    init: init,
    run:  run,
    ibuf_desc: {NULL},
    obuf_desc: {hpguppi_input_databuf_create}
};

static __attribute__((constructor)) void ctor()
{
  register_hashpipe_thread(&thread_desc);
}

// vi: set ts=2 sw=2 et :
