file(GLOB FBS_NAMES "${FBS_DIR_FULL_PREFIX}/*.fbs")

set(GENERATED_FILES "")

# Υπολογισμός του path προς το flatc (έχουμε ήδη βάλει add_subdirectory για flatbuffers)
set(FLATC_EXECUTABLE "${PROJECT_BINARY_DIR}/bin/flatc")

foreach (FILE ${FBS_NAMES})
    get_filename_component(FBS_NAME ${FILE} NAME_WE)  # e.g., message
    set(HEADER_NAME "${FBS_NAME}_generated.h")
    set(OUTPUT_PATH "${FBS_INCLUDE_PREFIX}/${HEADER_NAME}")

    add_custom_command(
            OUTPUT ${OUTPUT_PATH}
            COMMAND ${FLATC_EXECUTABLE} --cpp --scoped-enums -o ${FBS_INCLUDE_PREFIX} ${FILE}
            DEPENDS ${FILE} ${FLATC_EXECUTABLE}
            COMMENT "Generating ${HEADER_NAME} from ${FBS_NAME}.fbs"
    )

    list(APPEND GENERATED_FILES ${OUTPUT_PATH})
endforeach ()

add_custom_target(fbs-generation ALL DEPENDS ${GENERATED_FILES})