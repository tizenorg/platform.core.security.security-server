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
 * @file        privilege.cpp
 * @author      Michal Witanowski (m.witanowski@samsung.com)
 * @brief       Implementation of service encapsulating libprivilege-control.
 */

#include <memory>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <privilege-control.h>

#include <sys/smack.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <privilege.h>
#include <protocols.h>
#include <security-server.h>
#include <privilege-control.h>

namespace {

// interface ids
const SecurityServer::InterfaceID PRIVILEGE_CONTROL_MODIFY = 0;
const SecurityServer::InterfaceID PRIVILEGE_CONTROL_GET = 1;

} // namespace anonymous

namespace SecurityServer {

PrivilegeControlSevice::PrivilegeControlSevice()
{
    m_transactionInProgress = false;
}

GenericSocketService::ServiceDescriptionVector PrivilegeControlSevice::GetServiceDescription()
{
    return ServiceDescriptionVector {
        { SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_MODIFY,
          "security-server::libprivilege-control-modify",
          PRIVILEGE_CONTROL_MODIFY },

        { SERVICE_SOCKET_LIBPRIVILEGE_CONTROL_GET,
          "*",
          PRIVILEGE_CONTROL_GET }
    };
}

void PrivilegeControlSevice::accept(const AcceptEvent &event)
{
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void PrivilegeControlSevice::write(const WriteEvent &event)
{
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void PrivilegeControlSevice::process(const ReadEvent &event)
{
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, info.buffer, info.interfaceID));
}

void PrivilegeControlSevice::close(const CloseEvent &event)
{
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

bool PrivilegeControlSevice::processOne(const ConnectionID &conn, MessageBuffer &buffer,
                                        InterfaceID interfaceID)
{
    LogDebug("Iteration begin");

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    MessageBuffer send;
    bool retval = false;
    switch (interfaceID)
    {
        case PRIVILEGE_CONTROL_GET:
            retval = processGetAction(buffer, send);
            break;

        case PRIVILEGE_CONTROL_MODIFY:
            retval = processModifyAction(buffer, send);
            break;

        default:
            LogDebug("Wrong interface");
            break;
    }

    if (retval) {
        //send response
        m_serviceManager->Write(conn, send.Pop());
    } else {
        LogDebug("Closing socket because of error");
        m_serviceManager->Close(conn);
    }

    return retval;
}

bool PrivilegeControlSevice::processGetAction(MessageBuffer &buffer, MessageBuffer &send)
{
    // commonly used arguments
    std::string name, type, path, pkg_id;
    int temp;

    Deserialization::Deserialize(buffer, temp);
    auto action = static_cast<LibprivilegeControlGetAction>(temp);
    int result = SECURITY_SERVER_API_ERROR_SERVER_ERROR;

    Try {

    switch (action)
    {
        case LibprivilegeControlGetAction::APP_ID_FROM_SOCKET: {
            Deserialization::Deserialize(buffer, temp); // sockfd
            LogDebug("sockfd: " << temp);
            char* app_id = perm_app_id_from_socket(temp);

            if (nullptr == app_id) {
                Serialization::Serialize(send, PC_ERR_INVALID_OPERATION);
            }
            else {
                std::string app_id_str(app_id);
                free(app_id);
                Serialization::Serialize(send, PC_OPERATION_SUCCESS);
                Serialization::Serialize(send, app_id_str);
            }

            break;
        }

        case LibprivilegeControlGetAction::GET_PERMISSIONS: {
            Deserialization::Deserialize(buffer, temp); // app type
            LogDebug("app_type: " << temp);

            char** pp_permissions;
            result = perm_get_permissions(&pp_permissions, static_cast<app_type_t>(temp));
            Serialization::Serialize(send, result);

            if (result == PC_OPERATION_SUCCESS) {
                // convert char** to std::vector<std::string>
                std::vector<std::string> permissions;
                if (nullptr != pp_permissions) {
                    for (size_t i = 0; pp_permissions[i] != nullptr; ++i) {
                        permissions.push_back(std::string(pp_permissions[i]));
                        free(pp_permissions[i]);
                    }
                }
                Serialization::Serialize(send, permissions);
            }

            free(pp_permissions);
            break;
        }

        case LibprivilegeControlGetAction::APP_HAS_PERMISSION: {
            std::string permission;
            Serialization::Serialize(send, std::string(pkg_id));
            Deserialization::Deserialize(buffer, temp); // app type
            Deserialization::Deserialize(buffer, permission);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_type: " << temp);
            LogDebug("permission: " << permission);

            bool is_enabled = false;
            result = perm_app_has_permission(pkg_id.c_str(), static_cast<app_type_t>(temp), permission.c_str(), &is_enabled);

            Serialization::Serialize(send, result);
            Serialization::Serialize(send, is_enabled);
            break;
        }

        case LibprivilegeControlGetAction::GET_APPS_WITH_PERMISSION: {
            std::string permission;
            Deserialization::Deserialize(buffer, temp); // app type
            Deserialization::Deserialize(buffer, permission);
            LogDebug("app_type: " << temp);
            LogDebug("permission: " << permission);

            perm_app_status_t* apps_status;
            size_t apps_number;
            result = perm_get_apps_with_permission(&apps_status, &apps_number,
                                                   static_cast<app_type_t>(temp),
                                                   permission.c_str());
            Serialization::Serialize(send, result);

            if (result == PC_OPERATION_SUCCESS) {
                Serialization::Serialize(send, apps_number);
                // send perm_app_status_t structures
                for (size_t i = 0; i < apps_number; ++i) {
                    Serialization::Serialize(send, std::string(apps_status[i].app_id));
                    Serialization::Serialize(send, apps_status[i].is_enabled);
                    Serialization::Serialize(send, apps_status[i].is_permanent);
                }
            }

            // TODO: what if Serialization::Serialize throws an exception?
            perm_free_apps_list(apps_status, apps_number);
            break;
        }

        case LibprivilegeControlGetAction::APP_GET_PATHS: {
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, temp); // app path type
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_path_type: " << temp);

            char** pp_paths;
            result = perm_app_get_paths(pkg_id.c_str(), static_cast<app_path_type_t>(temp), &pp_paths);
            Serialization::Serialize(send, result);

            if (result == PC_OPERATION_SUCCESS) {
                // convert char** to std::vector<std::string>
                std::vector<std::string> paths;
                if (nullptr != pp_paths) {
                    for (size_t i = 0; pp_paths[i] != NULL; ++i) {
                        paths.push_back(std::string(pp_paths[i]));
                        free(pp_paths[i]);
                    }
                }
                Serialization::Serialize(send, paths);
                free(pp_paths);
            }

            break;
        }

        case LibprivilegeControlGetAction::APP_GET_PERMISSIONS: {
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, temp); // app type
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_path_type: " << temp);

            char** pp_permissions;
            result = perm_app_get_permissions(pkg_id.c_str(), static_cast<app_type_t>(temp), &pp_permissions);
            Serialization::Serialize(send, result);

            if (PC_OPERATION_SUCCESS == result) {
                // convert char** to std::vector<std::string>
                std::vector<std::string> permissions;
                if (nullptr != pp_permissions) {
                    for (size_t i = 0; pp_permissions[i] != nullptr; ++i) {
                        permissions.push_back(std::string(pp_permissions[i]));
                        free(pp_permissions[i]);
                    }
                }
                Serialization::Serialize(send, permissions);
                free(pp_permissions);
            }

            break;
        }

        default:
            LogError("Invalid 'get' action.");
            return false;
    }

    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    return true;
}

bool PrivilegeControlSevice::processModifyAction(MessageBuffer &buffer, MessageBuffer &send)
{
    // commonly used arguments
    std::string name, type, path, pkg_id;
    int temp;

    Deserialization::Deserialize(buffer, temp);
    auto action = static_cast<LibprivilegeControlModifyAction>(temp);
    int result = SECURITY_SERVER_API_ERROR_SERVER_ERROR;

    Try {

    switch (action)
    {
        case LibprivilegeControlModifyAction::APP_SET_PRIVILEGE: {
            Deserialization::Deserialize(buffer, name);
            Deserialization::Deserialize(buffer, type);
            Deserialization::Deserialize(buffer, path);
            LogDebug("name: " << name);
            LogDebug("type: " << type);
            LogDebug("path: " << path);

            result = perm_app_set_privilege(name.c_str(), type.c_str(), path.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_INSTALL: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            result = perm_app_install(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_UNINSTALL: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            result = perm_app_uninstall(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_ENABLE_PERMISSIONS: {
            bool persistent;
            std::vector<std::string> permissions;
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, temp);  // app_type
            Deserialization::Deserialize(buffer, permissions);
            Deserialization::Deserialize(buffer, persistent);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_type: " << temp);
            LogDebug("persisitent: " << persistent);

            // create null terminated array of strigns
            std::unique_ptr<const char *[]>
            pp_permissions(new (std::nothrow) const char* [permissions.size() + 1]);
            if (nullptr == permissions.data()) {
                LogError("Allocation error");
                return false;
            }
            for (size_t i = 0; i < permissions.size(); ++i) {
                pp_permissions[i] = permissions[i].c_str();
            }
            pp_permissions[permissions.size()] = nullptr;

            result = perm_app_enable_permissions(pkg_id.c_str(), static_cast<app_type_t>(temp),
                                                 pp_permissions.get(), persistent);
            Serialization::Serialize(send, result);
            break;
        }


        // TODO: merge with APP_ENABLE_PERMISSION
        case LibprivilegeControlModifyAction::APP_DISABLE_PERMISSIONS: {
            std::vector<std::string> permissions;
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, temp);  // app_type
            Deserialization::Deserialize(buffer, permissions);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_type: " << temp);

            // create null terminated array of strigns
            std::unique_ptr<const char *[]>
            pp_permissions(new (std::nothrow) const char* [permissions.size() + 1]);
            if (nullptr == permissions.data()) {
                LogError("Allocation error");
                return false;
            }
            for (size_t i = 0; i < permissions.size(); ++i) {
                pp_permissions[i] = permissions[i].c_str();
            }
            pp_permissions[permissions.size()] = nullptr;

            result = perm_app_disable_permissions(pkg_id.c_str(), static_cast<app_type_t>(temp),
                                                  pp_permissions.get());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_SETUP_PERMISSIONS: {
            // TODO
            std::vector<std::string> permissions;
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, temp);  // app_type
            Deserialization::Deserialize(buffer, permissions);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_type: " << temp);

            // create null terminated array of strigns
            std::unique_ptr<const char *[]>
            pp_smack_rules_set(new (std::nothrow) const char *[permissions.size() + 1]);
            if (nullptr == permissions.data()) {
                LogError("Allocation error");
                return false;
            }
            for (size_t i = 0; i < permissions.size(); ++i) {
                pp_smack_rules_set[i] = permissions[i].c_str();
            }
            pp_smack_rules_set[permissions.size()] = nullptr;

            result = perm_app_setup_permissions(pkg_id.c_str(), static_cast<app_type_t>(temp),
                                                pp_smack_rules_set.get());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_REVOKE_PERMISSION: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            result = perm_app_revoke_permissions(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_RESET_PERMISSIONS: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            result = perm_app_reset_permissions(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_SETUP_PATH: {
            std::string pkg_id, path, optional;
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, path);
            Deserialization::Deserialize(buffer, temp); // app path type
            Deserialization::Deserialize(buffer, optional);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("path: " << path);
            LogDebug("app_path_type: " << temp);
            LogDebug("optional: " << optional);

            result = perm_app_setup_path(pkg_id.c_str(), path.c_str(),
                                         static_cast<app_path_type_t>(temp), optional.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_REMOVE_PATH: {
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, path);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("path: " << path);

            result = perm_app_remove_path(pkg_id.c_str(), path.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::APP_ADD_FRIEND: {
            std::string pkg_id1, pkg_id2;
            Deserialization::Deserialize(buffer, pkg_id1);
            Deserialization::Deserialize(buffer, pkg_id2);
            LogDebug("pkg_id1: " << pkg_id1);
            LogDebug("pkg_id2: " << pkg_id2);

            result = perm_app_add_friend(pkg_id1.c_str(), pkg_id2.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::ADD_API_FEATURE: {
            std::string api_feature_name;
            std::vector<std::string> smack_rules_set;
            std::vector<unsigned int> db_gids;
            Deserialization::Deserialize(buffer, temp); // app type
            Deserialization::Deserialize(buffer, api_feature_name);
            Deserialization::Deserialize(buffer, smack_rules_set);
            Deserialization::Deserialize(buffer, db_gids);
            LogDebug("app_type: " << temp);
            LogDebug("api_feature_name: " << api_feature_name);

            // create null terminated array of strigns
            std::unique_ptr<const char *[]>
            pp_smack_rules_set(new (std::nothrow) const char* [smack_rules_set.size() + 1]);
            if (nullptr == pp_smack_rules_set.get()) {
                LogError("Allocation error");
                return false;
            }
            for (size_t i = 0; i < smack_rules_set.size(); ++i) {
                pp_smack_rules_set[i] = smack_rules_set[i].c_str();
            }
            pp_smack_rules_set[smack_rules_set.size()] = nullptr;

            result = perm_add_api_feature(static_cast<app_type_t>(temp), api_feature_name.c_str(),
                                          pp_smack_rules_set.get(), db_gids.data(), db_gids.size());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::BEGIN: {
            // TODO: save sender pid, mark started transaction, discard other pids
            result = perm_begin();
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::END: {
            // TODO: end transaction
            result = perm_end();
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlModifyAction::ROLLBACK: {
            // TODO: end transaction
            result = perm_rollback();
            Serialization::Serialize(send, result);
            break;
        }

        default:
            LogError("Invalid 'modify' action.");
            return false;
    }

    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    return true;
}

} // namespace SecurityServer
