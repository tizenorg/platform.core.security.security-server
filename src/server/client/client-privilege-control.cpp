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
#include <stdarg.h>        // for va_list

using namespace SecurityServer;

/*
 * Verifies if a C-string is not null or empty.
 * Used is most of functions below.
 */
#define CHECK_STRING(str) if ((nullptr == str) || (0 == strlen(str))) {     \
                              LogError(#str " is NULL or empty");           \
                              return PC_ERR_INVALID_PARAM; \
                          }

/*
 * Verifies if an argument is not NULL.
 * Used is most of functions below.
 */
#define CHECK_NOT_NULL(var) if (nullptr == var) {             \
                                LogError(#var " is NULL");    \
                                return PC_ERR_INVALID_PARAM;  \
                            }

/*
 * Send a message to the Security Server using specified socket.
 * This 5 lines of code are uses in all the functions below.
 * \par     socket  destination socket name
 */
#define SEND_TO_SERVER(socket)                                              \
result = sendToServer(socket, send.Pop(), recv);                            \
if (result != SECURITY_SERVER_API_SUCCESS) {                                \
    LogDebug("Error in sendToServer. Error code: " << result);              \
    return result;                                                          \
}


SECURITY_SERVER_API
int security_server_app_set_privilege(const char* name, const char* type, const char* path)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(name);
    CHECK_STRING(type);
    CHECK_STRING(path);
    LogDebug("name: " << name << ", type: " << type << ", path: " << path);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_SET_PRIVILEGE));
        Serialization::Serialize(send, std::string(name));
        Serialization::Serialize(send, std::string(type));
        Serialization::Serialize(send, std::string(path));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
char* security_server_app_id_from_socket(int sockfd)
{
    LogDebug(__func__ << " called");
    LogDebug("sockfd: " << sockfd);

    try {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlGetAction::APP_ID_FROM_SOCKET));
        Serialization::Serialize(send, sockfd);
        int result = sendToServer(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_GET, send.Pop(), recv);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << result);
            return NULL;
        }

        //receive response from the server
        Deserialization::Deserialize(recv, result);

        if (result == PC_OPERATION_SUCCESS) {
            std::string app_id;
            Deserialization::Deserialize(recv, app_id);
            return strdup(app_id.c_str());
        }

        return NULL;

    } catch (MessageBuffer::Exception::Base &e) {
        LogError("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    } catch (...) {
        LogError("Unknown exception occured");
    }

    return NULL;
}

SECURITY_SERVER_API
int security_server_app_install(const char* pkg_id)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_INSTALL));
        Serialization::Serialize(send, std::string(pkg_id));

        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_uninstall(const char* pkg_id)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_UNINSTALL));
        Serialization::Serialize(send, std::string(pkg_id));

        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_setup_permissions(const char* pkg_id, app_type_t app_type,
                                          const char** perm_list)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_NOT_NULL(perm_list);
    CHECK_STRING(pkg_id);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("app_type: " << app_type);

    return try_catch([&] {
        MessageBuffer send, recv;

        std::vector<std::string> permissions;
        for (size_t i = 0; perm_list[i] != nullptr; ++i) {
            permissions.push_back(perm_list[i]);
        }

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_SETUP_PERMISSIONS));
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, permissions);

        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_revoke_permissions(const char* pkg_id)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_REVOKE_PERMISSION));
        Serialization::Serialize(send, std::string(pkg_id));

        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_reset_permissions(const char* pkg_id)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_RESET_PERMISSIONS));
        Serialization::Serialize(send, std::string(pkg_id));

        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_has_permission(const char *pkg_id, app_type_t app_type,
                                       const char *permission_name, bool *is_enabled)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    CHECK_STRING(permission_name);
    CHECK_NOT_NULL(is_enabled);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("app_type: " << app_type);
    LogDebug("permission_name: " << permission_name);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlGetAction::APP_HAS_PERMISSION));
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, std::string(permission_name));

        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_GET);

        //receive response from the server
        bool enabled;
        Deserialization::Deserialize(recv, result);
        Deserialization::Deserialize(recv, enabled);
        *is_enabled = enabled;
        return result;
    });
}

SECURITY_SERVER_API
int security_server_get_permissions(char ***ppp_permissions, app_type_t app_type)
{
    int result;
    LogDebug(__func__ << " called");
    LogDebug("app_type: " << app_type);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlGetAction::GET_PERMISSIONS));
        Serialization::Serialize(send, static_cast<int>(app_type));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_GET);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        if (PC_OPERATION_SUCCESS == result) {
            std::vector<std::string> permissions;
            Deserialization::Deserialize(recv, permissions);

            (*ppp_permissions) = (char **)malloc(sizeof(**ppp_permissions) * (permissions.size() + 1));
            if (nullptr == (*ppp_permissions)) {
                LogError("Cannot allocate memory");
                return PC_ERR_MEM_OPERATION;
            }

            for (size_t i = 0; i < permissions.size(); ++i) {
                (*ppp_permissions)[i] = strdup(permissions[i].c_str());
            }
            (*ppp_permissions)[permissions.size()] = nullptr;

            // TODO: better error checking
        }
        return result;
    });
}

SECURITY_SERVER_API
int security_server_get_apps_with_permission(perm_app_status_t **pp_apps, size_t *pi_apps_number,
                                             app_type_t app_type, const char *s_permission_name)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(s_permission_name);
    LogDebug("app_type: " << app_type);
    LogDebug("s_permission_name: " << s_permission_name);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlGetAction::GET_APPS_WITH_PERMISSION));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, std::string(s_permission_name));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_GET);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        if (PC_OPERATION_SUCCESS == result) {
            size_t apps_number;
            Deserialization::Deserialize(recv, apps_number);
            (*pi_apps_number) = apps_number;

            (*pp_apps) = (perm_app_status_t*)malloc(sizeof(perm_app_status_t) * apps_number);
            if (nullptr == (*pp_apps)) {
                LogError("Cannot allocate memory");
                return PC_ERR_MEM_OPERATION;
            }

            std::string app_id;
            for (size_t i = 0; i < apps_number; ++i) {
                Deserialization::Deserialize(recv, app_id);
                Deserialization::Deserialize(recv, (*pp_apps)[i].is_enabled);
                Deserialization::Deserialize(recv, (*pp_apps)[i].is_permanent);
                (*pp_apps)[i].app_id = strdup(app_id.c_str());
                // TODO: error checking
            }

            *pi_apps_number = apps_number;
        }
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_get_permissions(const char *pkg_id, app_type_t app_type, char ***ppp_perm_list)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("app_type: " << app_type);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlGetAction::APP_GET_PERMISSIONS));
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, static_cast<int>(app_type));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_GET);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        if (PC_OPERATION_SUCCESS == result) {
            std::vector<std::string> permissions;
            Deserialization::Deserialize(recv, permissions);

            (*ppp_perm_list) = (char**)malloc(sizeof(char*) * (permissions.size() + 1));
            if (nullptr == *ppp_perm_list) {
                return PC_ERR_MEM_OPERATION;
            }

            for (size_t i = 0; i < permissions.size(); ++i)
            {
                (*ppp_perm_list)[i] = strdup(permissions[i].c_str());
                // TODO: error checking
            }
            (*ppp_perm_list)[permissions.size()] = nullptr;
        }
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_setup_path(const char* pkg_id, const char* path,
                                   app_path_type_t app_path_type, ...)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    CHECK_STRING(path);
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
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_SETUP_PATH));
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, std::string(path));
        Serialization::Serialize(send, static_cast<int>(app_path_type));
        Serialization::Serialize(send, std::string((nullptr != optional) ? optional : ""));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_get_paths(const char* pkg_id, app_path_type_t app_path_type,
                                  char*** ppp_paths)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("app_path_type: " << app_path_type);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlGetAction::APP_GET_PATHS));
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, static_cast<int>(app_path_type));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_GET);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        if (PC_OPERATION_SUCCESS == result)
        {
            std::vector<std::string> paths;
            Deserialization::Deserialize(recv, paths);

            (*ppp_paths) = (char**)malloc(sizeof(char*) * (paths.size() + 1));
            for (size_t i = 0; i < paths.size(); ++i) {
                (*ppp_paths)[i] = strdup(paths[i].c_str());
                // TODO: error checking
            }
            (*ppp_paths)[paths.size()] = nullptr;

            // TODO: strdup, etc....
        }
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_remove_path(const char* pkg_id, const char *path)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id);
    CHECK_STRING(path);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("path: " << path);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_REMOVE_PATH));
        Serialization::Serialize(send, std::string(pkg_id));
        Serialization::Serialize(send, std::string(path));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_app_add_friend(const char* pkg_id1, const char* pkg_id2)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(pkg_id1);
    CHECK_STRING(pkg_id2);
    LogDebug("pkg_id1: " << pkg_id1);
    LogDebug("pkg_id2: " << pkg_id2);

    return try_catch([&] {
        MessageBuffer send, recv;

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::APP_ADD_FRIEND));
        Serialization::Serialize(send, std::string(pkg_id1));
        Serialization::Serialize(send, std::string(pkg_id2));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_add_api_feature(app_type_t app_type, const char* api_feature_name,
                                    const char** set_smack_rule_set, const gid_t* list_of_db_gids,
                                    size_t list_size)
{
    int result;
    LogDebug(__func__ << " called");
    CHECK_STRING(api_feature_name);
    CHECK_NOT_NULL(set_smack_rule_set);
    LogDebug("app_type: " << app_type);
    LogDebug("api_feature_name: " << api_feature_name);

    return try_catch([&] {
        MessageBuffer send, recv;

        std::vector<std::string> smack_rules_set;
        for (; *set_smack_rule_set; ++set_smack_rule_set) {
            smack_rules_set.push_back(*set_smack_rule_set);
        }

        std::vector<unsigned int> db_gids;
        if (nullptr != list_of_db_gids) {
            for (size_t i = 0; i<list_size; ++i) {
                db_gids.push_back(static_cast<unsigned int>(list_of_db_gids[i]));
            }
        }

        //put arguments into buffer
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::ADD_API_FEATURE));
        Serialization::Serialize(send, static_cast<int>(app_type));
        Serialization::Serialize(send, std::string(api_feature_name));
        Serialization::Serialize(send, smack_rules_set);
        Serialization::Serialize(send, db_gids);
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_perm_begin()
{
    int result;
    LogDebug(__func__ << " called");

    return try_catch([&] {
        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::BEGIN));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_perm_end()
{
    int result;
    LogDebug(__func__ << " called");

    return try_catch([&] {
        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::END));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_perm_rollback()
{
    int result;
    LogDebug(__func__ << " called");

    return try_catch([&] {
        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::ROLLBACK));
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}

SECURITY_SERVER_API
int security_server_add_additional_rules(const char** set_smack_rule_set)
{
    int result;
    LogDebug(__func__ << " called");

    return try_catch([&] {
        std::vector<std::string> smack_rules_set;
        if (nullptr != set_smack_rule_set) {
            for (; *set_smack_rule_set; ++set_smack_rule_set) {
                smack_rules_set.push_back(*set_smack_rule_set);
            }
        }
        else {
            LogError("set_smack_rule_set is NULL");
            return PC_ERR_INVALID_PARAM;
        }

        //put arguments into buffer
        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(LibprivilegeControlModifyAction::ADD_ADDITIONAL_RULES));
        Serialization::Serialize(send, smack_rules_set);
        SEND_TO_SERVER(SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY);

        //receive response from the server
        Deserialization::Deserialize(recv, result);
        return result;
    });
}
