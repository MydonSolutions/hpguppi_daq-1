#ifndef BLADE_ATA_MODE_H_CONFIG_H
#define BLADE_ATA_MODE_H_CONFIG_H

#define BLADE_ATA_MODE_H_CHANNELIZER_RATE 1 // [1, 4]; <= 1 mitigates the channlisation

#define BLADE_ATA_MODE_H_INPUT_NANT 20
#define BLADE_ATA_MODE_H_INPUT_NCOMPLEX_BYTES 2

#define BLADE_ATA_MODE_H_ANT_NCHAN 192
#define BLADE_ATA_MODE_H_NTIME 8192
#define BLADE_ATA_MODE_H_NPOL 2

#define BLADE_ATA_MODE_H_OUTPUT_NBEAM 2
#define BLADE_ATA_MODE_H_ACCUMULATE_RATE 8 // [1]; <= 1 mitigates the accumulation
#define BLADE_ATA_MODE_H_OUTPUT_NPOL 1
#define BLADE_ATA_MODE_H_OUTPUT_INCOHERENT_BEAM false

#define BLADE_ATA_MODE_H_OUTPUT_N_BYTES 4
#define BLADE_ATA_MODE_H_OUTPUT_ELEMENT_T F32

#define BLADE_ATA_MODE_H_OUTPUT_MEMCPY2D_PAD 0 // zero makes memcpy2D effectively 1D
#define BLADE_ATA_MODE_H_OUTPUT_MEMCPY2D_WIDTH 8192

#define BLADE_ATA_MODE_H_OUTPUT_MEMCPY2D_DPITCH (BLADE_ATA_MODE_H_OUTPUT_MEMCPY2D_WIDTH+BLADE_ATA_MODE_H_OUTPUT_MEMCPY2D_PAD)

#define BLADE_ATA_MODE_H_OUTPUT_DATA_SIZE (\
  (BLADE_ATA_MODE_H_OUTPUT_NBEAM + (BLADE_ATA_MODE_H_OUTPUT_INCOHERENT_BEAM ? 1 : 0)) *\
  BLADE_ATA_MODE_H_ANT_NCHAN *\
  BLADE_ATA_MODE_H_NTIME *\
  BLADE_ATA_MODE_H_ACCUMULATE_RATE *\
  BLADE_ATA_MODE_H_OUTPUT_NPOL *\
  BLADE_ATA_MODE_H_OUTPUT_N_BYTES /\
  1\
)

#define BLADE_ATA_MODE_H_DATA_SIZE BLADE_ATA_MODE_H_OUTPUT_DATA_SIZE

#endif