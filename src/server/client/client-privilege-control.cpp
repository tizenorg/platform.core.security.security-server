/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file        client-privilege-control.cpp
 * @author      Michal Witanowski (m.witanowski@samsung.com)
 * @version     1.0
 * @brief       This file contains client-side libprivilege-control encapsulation
 */

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>

#include <privilege-control.h>
#include <security-server.h>

#include <stdio.h>
#include <stdarg.h>     // for va_list
#include <unistd.h>     // for getpid()

using namespace SecurityServer;

bool check_string(const char* str, const char* str_name)
{
    if ((nullptr == str) || (0 == strlen(str))) {
        LogError(str_name << " is nullptr or empty");
        return false;
    }
    return true;
}

/*
 * Verifies if a C-string is not null or empty.
 * Used is most of functions below. Returns true if 'str' is valid.
 */
#define CHECK_STRING(str) check_string(str, #str)

/*
 * Append header to message buffer being sent do the Security Server,
 * which contains PID and action enum.
 */
void makeHeader(MessageBuffer& buffer, LibprivilegeControlAction action)
{
    pid_t pid = getpid();
    Serialization::Serialize(buffer, pid);
    Serialization::Serialize(buffer, static_cast<int>(action));
}

SECURITY_SERVER_API
int security_server_app_install(const char* pkg_id)
{
    LogDebug(__func__ << " called");

    if (!CHECK_STRING(pkg_id)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        makeHeader(send, LibprivilegeControlAction::APP_INSTALL);
        Serialization::Serialize(send, std::string(pkg_id));

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_uninstall(const char* pkg_id)
{
    LogDebug(__func__ << " called");

    if (!CHECK_STRING(pkg_id)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        makeHeader(send, LibprivilegeControlAction::APP_UNINSTALL);
        Serialization::Serialize(send, std::string(pkg_id));

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_revoke_permissions(const char* pkg_id)
{
    LogDebug(__func__ << " called");

    if (!CHECK_STRING(pkg_id)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        makeHeader(send, LibprivilegeControlAction::APP_REVOKE_PERMISSIONS);
        Serialization::Serialize(send, std::string(pkg_id));

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_reset_permissions(const char* pkg_id)
{
    LogDebug(__func__ << " called");

    if (!CHECK_STRING(pkg_id)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        makeHeader(send, LibprivilegeControlAction::APP_RESET_PERMISSIONS);
        Serialization::Serialize(send, std::string(pkg_id));

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_setup_path(const char* pkg_id, const char* path, int app_path_type, ...)
{
    LogDebug(__func__ << " called");

    if (!CHECK_STRING(pkg_id) || !CHECK_STRING(path)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("path: " << path);
    LogDebug("app_path_type: " << app_path_type);

    // get optional argument of this variadic function
    va_list ap;
    va_start(ap, app_path_type);
    const char* optional = va_arg(ap, const char*);
    va_end(ap);

    if (nullptr != optional) {
        LogDebug("optional parameter: " << app_path_type);
    }

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        makeHeader(send, LibprivilegeControlAction::APP_SETUP_PATH);
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, std::string(path));
        Serialization::Serialize(send, app_path_type);
        Serialization::Serialize(send, std::string((nullptr != optional) ? optional : ""));

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_add_api_feature(int app_type, const char* api_feature_name,
                                    const char** set_smack_rule_set, const gid_t* list_of_db_gids,
                                    size_t list_size)
{
    LogDebug(__func__ << " called");

    if (!CHECK_STRING(api_feature_name)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }
    LogDebug("app_type: " << app_type);
    LogDebug("api_feature_name: " << api_feature_name);

    return try_catch([&] {
        MessageBuffer send, recv;
        std::vector<std::string> smack_rules_set;
        std::vector<unsigned int> db_gids;

        if (nullptr != set_smack_rule_set) {
            for (size_t i = 0; set_smack_rule_set[i]; ++i) {
                LogDebug("set_smack_rule_set[" << i << "]: " << set_smack_rule_set[i]);
                smack_rules_set.push_back(set_smack_rule_set[i]);
            }
        }

        if (nullptr != list_of_db_gids) {
            for (size_t i = 0; i<list_size; ++i) {
                LogDebug("db_gids[" << i << "]: " << list_of_db_gids[i]);
                db_gids.push_back(static_cast<unsigned int>(list_of_db_gids[i]));
            }
        }

        //put arguments into buffer
        makeHeader(send, LibprivilegeControlAction::ADD_API_FEATURE);
        Serialization::Serialize(send, app_type);
        Serialization::Serialize(send, std::string(api_feature_name));
        Serialization::Serialize(send, smack_rules_set);
        Serialization::Serialize(send, db_gids);

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_perm_begin()
{
    LogDebug(__func__ << " called");

    return try_catch([&] {
        MessageBuffer send, recv;
        makeHeader(send, LibprivilegeControlAction::BEGIN);

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_perm_end()
{
    LogDebug(__func__ << " called");

    return try_catch([&] {
        MessageBuffer send, recv;
        makeHeader(send, LibprivilegeControlAction::END);

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_perm_rollback()
{
    LogDebug(__func__ << " called");

    return try_catch([&] {
        MessageBuffer send, recv;
        makeHeader(send, LibprivilegeControlAction::ROLLBACK);

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_enable_permissions(const char *pkg_id, int app_type,
                                           const char **perm_list, int persistent)
{
    LogDebug(__func__ << " called");

    // verify parameters
    if (!CHECK_STRING(pkg_id)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }

    if (nullptr == perm_list) {
        LogDebug("perm_list is NULL");
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }

    LogDebug("app_type: " << app_type);
    LogDebug("persistent: " << persistent);
    LogDebug("app_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        std::vector<std::string> permissions_list;
        for (int i = 0; nullptr != perm_list[i]; ++i) {
            LogDebug("perm_list[" << i << "]: " << perm_list[i]);
            permissions_list.push_back(perm_list[i]);
        }

        makeHeader(send, LibprivilegeControlAction::APP_ENABLE_PERMISSIONS);
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, app_type);
        Serialization::Serialize(send, persistent);
        Serialization::Serialize(send, permissions_list);

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        //receive response from server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_disable_permissions(const char *pkg_id, int app_type,
                                            const char **perm_list)
{
    LogDebug(__func__ << " called");

    // verify parameters
    if (!CHECK_STRING(pkg_id)) {
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }

    if (nullptr == perm_list) {
        LogDebug("perm_list is NULL");
        return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    }

    LogDebug("app_type: " << app_type);
    LogDebug("app_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        std::vector<std::string> permissions_list;
        for (int i = 0; nullptr != perm_list[i]; ++i) {
            LogDebug("perm_list[" << i << "]: " << perm_list[i]);
            permissions_list.push_back(perm_list[i]);
        }

        makeHeader(send, LibprivilegeControlAction::APP_DISABLE_PERMISSIONS);
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, app_type);
        Serialization::Serialize(send, permissions_list);

        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            return result;
        }

        Deserialization::Deserialize(recv, result);
        return result;
    });
}
