PKG_CHECK_MODULES(PCH_DEP
    dlog
    REQUIRED
    )

SET(PCH_PATH ${PROJECT_SOURCE_DIR}/src/server/dpl)

SET(PCH_SOURCES
    ${PCH_PATH}/log/include/dpl/log/abstract_log_provider.h
    ${PCH_PATH}/log/include/dpl/log/audit-smack-log.h
    ${PCH_PATH}/log/include/dpl/log/dlog_log_provider.h
    ${PCH_PATH}/log/include/dpl/log/log.h
    ${PCH_PATH}/log/include/dpl/log/old_style_log_provider.h
    ${PCH_PATH}/core/include/dpl/assert.h
    ${PCH_PATH}/core/include/dpl/binary_queue.h
    ${PCH_PATH}/core/include/dpl/colors.h
    ${PCH_PATH}/core/include/dpl/exception.h
    ${PCH_PATH}/core/include/dpl/fstream_accessors.h
    ${PCH_PATH}/core/include/dpl/noncopyable.h
    ${PCH_PATH}/core/include/dpl/noreturn.h
    ${PCH_PATH}/core/include/dpl/serialization.h
    ${PCH_PATH}/core/include/dpl/singleton.h
    ${PCH_PATH}/core/include/dpl/singleton_impl.h
    ${PCH_PATH}/core/include/dpl/singleton_safe_impl.h
    )

INCLUDE_DIRECTORIES(SYSTEM
    ${PCH_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${PCH_PATH}/core/include
    ${PCH_PATH}/log/include
    )

SET(_INCLIST '')
GET_DIRECTORY_PROPERTY(DIRINC INCLUDE_DIRECTORIES)
FOREACH(_inc ${DIRINC})
    LIST(APPEND _INCLIST "-I" ${_inc})
ENDFOREACH(_inc ${DIRINC})

SET(PCH_SOURCES_GCH)
FOREACH (_header ${PCH_SOURCES})
    LIST(APPEND PCH_SOURCES_GCH ${_header}.gch)
    SET(_args ${CMAKE_CXX_FLAGS})
    LIST(APPEND _args -c ${_header} -o ${_header}.gch)
    LIST(APPEND _args ${_INCLIST})
    LIST(APPEND _args -D_GNU_SOURCE -fPIC -fvisibility=default)
    SEPARATE_ARGUMENTS(_args)
    ADD_CUSTOM_COMMAND(OUTPUT ${_header}.gch
        COMMAND rm -f ${_header}.gch
        COMMAND ${CMAKE_CXX_COMPILER} ${CMAKE_CXX_COMPILER_ARG1} ${_args}
            DEPENDS ${_header})
ENDFOREACH(_header ${PCH_SOURCES})

ADD_LIBRARY(${TARGET_SERVER_PCH} OBJECT ${PCH_SOURCES})

#SET_TARGET_PROPERTIES(
#    ${TARGET_SERVER_PCH}
#    PROPERTIES
#        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
#    )

################################################################################
