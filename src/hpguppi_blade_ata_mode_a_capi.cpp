#include <cassert>
#include <memory>

#include "blade/base.hh"
#include "blade/runner.hh"
#include "blade/plan.hh"
#include "blade/pipelines/ata/mode_b.hh"

extern "C" {
#include "hpguppi_blade_ata_mode_a_capi.h"
}

using namespace Blade;
using namespace Blade::Pipelines::ATA;

using BladePipeline = ModeB<CI8, BLADE_ATA_MODE_A_OUTPUT_ELEMENT_T>;

static Vector<Device::CPU, F64> blockJulianDate({1});
static Vector<Device::CPU, F64> blockDut1({1});
static Vector<Device::CPU, U64> blockFrequencyChannelOffset({1});

static struct {
    U64 StepCount = 0;
    void* UserData = nullptr;
    std::unordered_map<U64, void*> InputPointerMap;
    std::unordered_map<U64, void*> OutputPointerMap;
    std::unordered_map<U64, size_t> InputIdMap;
    std::unordered_map<U64, size_t> OutputIdMap;
    
    struct {
        std::unique_ptr<Runner<BladePipeline>> B;
    } RunnersInstances;

    struct {
        blade_stateful_cb* InputBufferPrefetch;
        blade_input_buffer_fetch_cb* InputBufferFetch;
        blade_input_buffer_enqueued_cb* InputBufferEnqueued;
        blade_input_buffer_ready_cb* InputBufferReady;
        blade_output_buffer_fetch_cb* OutputBufferFetch;
        blade_output_buffer_ready_cb* OutputBufferReady;

        blade_clear_queued_cb* InputClear;
        blade_clear_queued_cb* OutputClear;
    } Callbacks;
} State;

bool blade_ata_a_initialize(
    struct blade_ata_mode_a_config ata_a_config,
    size_t numberOfWorkers,
    struct blade_ata_observation_meta* observationMeta,
    struct LonLatAlt* arrayReferencePosition,
    double* obs_phase_center_radecrad,
    double* beamCoordinates_radecrad,
    double* antennaPositions_xyz,
    double _Complex* antennaCalibrations
) {
    if (State.RunnersInstances.B) {
        BL_FATAL("Can't initialize because Blade Runner is already initialized.");
        throw Result::ASSERTION_ERROR;
    }

    std::vector<XYZ> antennaPositions(ata_a_config.inputDims.NANTS);
    std::vector<RA_DEC> beamCoordinates(ata_a_config.beamformerBeams);
    std::vector<CF64> antennaCalibrationsCpp(
            ata_a_config.inputDims.NANTS*\
            ata_a_config.inputDims.NCHANS*\
            ata_a_config.inputDims.NPOLS);
    int i;
    for(i = 0; i < ata_a_config.inputDims.NANTS; i++){
        antennaPositions[i].X = antennaPositions_xyz[i*3 + 0];
        antennaPositions[i].Y = antennaPositions_xyz[i*3 + 1];
        antennaPositions[i].Z = antennaPositions_xyz[i*3 + 2];
    }
    for(i = 0; i < ata_a_config.beamformerBeams; i++){
        beamCoordinates[i].RA = beamCoordinates_radecrad[i*2 + 0];
        beamCoordinates[i].DEC = beamCoordinates_radecrad[i*2 + 1];
    }
    memcpy(antennaCalibrationsCpp.data(), antennaCalibrations,
            antennaCalibrationsCpp.size()*sizeof(antennaCalibrationsCpp[0]));

    
    ArrayDimensions beamformerInputDimensions = ArrayDimensions({
        .A = ata_a_config.inputDims.NANTS,
        .F = ata_a_config.inputDims.NCHANS,
        .T = ata_a_config.inputDims.NTIME,
        .P = ata_a_config.inputDims.NPOLS,
    });

    State.RunnersInstances.B = Runner<BladePipeline>::New(
        numberOfWorkers,
        {
            .inputDimensions = beamformerInputDimensions,

            .preBeamformerChannelizerRate = ata_a_config.channelizerRate,

            .phasorObservationFrequencyHz = observationMeta->rfFrequencyHz,
            .phasorChannelBandwidthHz = observationMeta->channelBandwidthHz,
            .phasorTotalBandwidthHz = observationMeta->totalBandwidthHz,
            .phasorFrequencyStartIndex = observationMeta->frequencyStartIndex,
            .phasorReferenceAntennaIndex = observationMeta->referenceAntennaIndex,
            .phasorArrayReferencePosition = {
                .LON = arrayReferencePosition->LON,
                .LAT = arrayReferencePosition->LAT,
                .ALT = arrayReferencePosition->ALT
            },
            .phasorBoresightCoordinate = {
                .RA = obs_phase_center_radecrad[0],
                .DEC = obs_phase_center_radecrad[1]
            },
            .phasorAntennaPositions = antennaPositions,
            .phasorAntennaCoefficients = antennaCalibrationsCpp,
            .phasorBeamCoordinates = beamCoordinates,
            .phasorAntennaCoefficientChannelRate = ata_a_config.channelizerRate,

            .beamformerIncoherentBeam = BLADE_ATA_MODE_A_OUTPUT_INCOHERENT_BEAM,

            .detectorEnable = true,
            .detectorIntegrationSize = ata_a_config.integrationSize,
            .detectorNumberOfOutputPolarizations = ata_a_config.numberOfOutputPolarizations,

            .castBlockSize = ata_a_config.castBlockSize,
            .channelizerBlockSize = ata_a_config.channelizerBlockSize,
            .beamformerBlockSize = ata_a_config.beamformerBlockSize,
            .detectorBlockSize = ata_a_config.detectorBlockSize
        }
    );

    State.InputPointerMap.reserve(numberOfWorkers);
    State.OutputPointerMap.reserve(numberOfWorkers);
    State.InputIdMap.reserve(numberOfWorkers);
    State.OutputIdMap.reserve(numberOfWorkers);

    blockFrequencyChannelOffset[0] = 0;

    return true;
}

void blade_ata_a_terminate() {
    if (!State.RunnersInstances.B) {
        BL_WARN("Can't terminate because Blade Runner isn't initialized.");
        // throw Result::ASSERTION_ERROR;
    }

    for(const auto &[key, value]: State.InputIdMap) {
        State.Callbacks.InputClear(State.UserData, value);
    }
    State.InputIdMap.clear();
    for(const auto &[key, value]: State.OutputIdMap) {
        State.Callbacks.OutputClear(State.UserData, value);
    }
    State.OutputIdMap.clear();

    State.RunnersInstances.B.reset();
}

size_t blade_ata_a_get_input_size() {
    assert(State.RunnersInstances.B);
    return State.RunnersInstances.B->getWorker().getInputBuffer().dims().size();
}

size_t blade_ata_a_get_output_size() {
    assert(State.RunnersInstances.B);
    return State.RunnersInstances.B->getWorker().getOutputBuffer().dims().size();
}

void blade_ata_a_set_block_time_mjd(double mjd) {
    blockJulianDate.data()[0] = mjd;
}

void blade_ata_a_set_block_dut1(double dut1) {
    blockDut1.data()[0] = dut1;
}

void blade_ata_a_register_user_data(void* user_data) {
    State.UserData = user_data;
}

void blade_ata_a_register_input_buffer_prefetch_cb(blade_stateful_cb* f) {
    State.Callbacks.InputBufferPrefetch = f;
}

void blade_ata_a_register_input_buffer_fetch_cb(blade_input_buffer_fetch_cb* f) {
    State.Callbacks.InputBufferFetch = f;
}

void blade_ata_a_register_input_buffer_enqueued_cb(blade_input_buffer_enqueued_cb* f) {
    State.Callbacks.InputBufferEnqueued = f;
}

void blade_ata_a_register_input_buffer_ready_cb(blade_input_buffer_ready_cb* f) {
    State.Callbacks.InputBufferReady = f;
}

void blade_ata_a_register_output_buffer_fetch_cb(blade_output_buffer_fetch_cb* f) {
    State.Callbacks.OutputBufferFetch = f;
}

void blade_ata_a_register_output_buffer_ready_cb(blade_output_buffer_ready_cb* f) {
    State.Callbacks.OutputBufferReady = f;
}

void blade_ata_a_register_blade_queued_input_clear_cb(blade_clear_queued_cb* f) {
    State.Callbacks.InputClear = f;
}

void blade_ata_a_register_blade_queued_output_clear_cb(blade_clear_queued_cb* f) {
    State.Callbacks.OutputClear = f;
}

bool blade_ata_a_compute_step() {
    bool prefetch = State.Callbacks.InputBufferPrefetch(State.UserData);
    
    if(!State.RunnersInstances.B) {
        return false;
    }

    U64 callbackStep = 0;
    void* externalBuffer_input = nullptr;
    void* externalBuffer_output = nullptr;

    auto& ModeB = State.RunnersInstances.B; 
    if (prefetch) {
        ModeB->enqueue([&](auto& worker) {
            // Check if next runner has free slot.
            Plan::Available(ModeB);

            size_t bufferId_input;
            size_t bufferId_output;
            // Calls client callback to request empty input buffer.
            if (!State.Callbacks.InputBufferFetch(State.UserData, &externalBuffer_input, &bufferId_input)) {
                Plan::Skip();
            }

            if (!State.Callbacks.OutputBufferFetch(State.UserData, &externalBuffer_output, &bufferId_output)) {
                State.Callbacks.InputClear(State.UserData, bufferId_input);
                Plan::Skip();
            }

            // Keeps track of pointer for "ready" callback.
            State.InputPointerMap.insert({State.StepCount, externalBuffer_input});
            State.InputIdMap.insert({State.StepCount, bufferId_input});
            State.OutputPointerMap.insert({State.StepCount, externalBuffer_output});
            State.OutputIdMap.insert({State.StepCount, bufferId_output});

            // Create Memory::ArrayTensor from RAW pointer.
            auto input = ArrayTensor<Device::CPU, CI8>(externalBuffer_input, worker.getInputBuffer().dims());
            auto output = ArrayTensor<Device::CPU, F32>(externalBuffer_output, worker.getOutputBuffer().dims());

            // Transfer input memory to the pipeline.
            Plan::TransferIn(worker, 
                            blockJulianDate,
                            blockDut1,
                            blockFrequencyChannelOffset,
                            input);

            // Asynchronous CPU work
            State.Callbacks.InputBufferEnqueued(State.UserData, bufferId_input); // not optimal, move to spin-loop

            // Compute input data.
            Plan::Compute(worker);

            // Copy worker output to external output buffer.
            Plan::TransferOut(output, worker.getOutputBuffer(), worker);

            // Return job identity and increment counter.
            return State.StepCount++; 
        });
    }

    // Dequeue last runner job and recycle output buffer.
    if (ModeB->dequeue(&callbackStep)) {
        const auto& recycleBuffer_input = State.OutputPointerMap[callbackStep];
        const auto& recycleBufferId_input = State.OutputIdMap[callbackStep];
        const auto& recycleBuffer_output = State.OutputPointerMap[callbackStep];
        const auto& recycleBufferId_output = State.OutputIdMap[callbackStep];
        
        State.Callbacks.InputBufferReady(State.UserData, recycleBuffer_input, recycleBufferId_input);
        State.Callbacks.OutputBufferReady(State.UserData, recycleBuffer_output, recycleBufferId_output);
        State.InputPointerMap.erase(callbackStep);
        State.InputIdMap.erase(callbackStep);
        State.OutputPointerMap.erase(callbackStep);
        State.OutputIdMap.erase(callbackStep);
    }

    // Prevent memory clobber inside spin-loop.
    Plan::Loop();

    // Return if pipeline is computing something.
    return !(ModeB->empty());
}
