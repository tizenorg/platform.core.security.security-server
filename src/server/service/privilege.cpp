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

#include <sys/smack.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <privilege.h>
#include <protocols.h>
#include <security-server.h>
#include <privilege-control.h>

namespace {

// interface ids
const SecurityServer::InterfaceID PRIVILEGE_CONTROL_INTERFACE = 0;

} // namespace anonymous

namespace SecurityServer {

/*
 * Transaction timeout in milliseconds.
 * After this amount of time any in-progress transaction (started via security_server_perm_begin)
 * will be stopped (via perm_rollback). This will protect security server from blocking.
 */
const int TRANSACTION_TIMEOUT = 5000;

PrivilegeControlSevice::PrivilegeControlSevice()
{
    m_transactionInProgress = false;
    m_clientPid = 0;
}

GenericSocketService::ServiceDescriptionVector PrivilegeControlSevice::GetServiceDescription()
{
    return ServiceDescriptionVector {
        { SERVICE_SOCKET_LIBPRIVILEGE_CONTROL,
          "security-server::libprivilege-control",
          PRIVILEGE_CONTROL_INTERFACE },
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

    if (interfaceID != PRIVILEGE_CONTROL_INTERFACE) {
        LogDebug("Wrong interface");
    } else {
        retval = processAction(buffer, send);
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

bool PrivilegeControlSevice::processAction(MessageBuffer &buffer, MessageBuffer &send)
{
    // commonly used arguments
    std::string name, type, path, pkg_id;
    int temp;

    // deserialize client pid
    pid_t pid;
    Deserialization::Deserialize(buffer, pid);

    // deserialize LPC action
    Deserialization::Deserialize(buffer, temp);
    auto action = static_cast<LibprivilegeControlAction>(temp);


    if (action != LibprivilegeControlAction::APP_ID_FROM_SOCKET)
    {
        if (m_transactionInProgress)
        {
            // measure time since last action
            Millisecs duration(
                    std::chrono::duration_cast<Millisecs>(Clock::now() - m_transactionStart));

            // timeout exceeded
            if (duration.count() > TRANSACTION_TIMEOUT) {
                perm_rollback();
                m_transactionInProgress = false;
            }
        }

        if (m_transactionInProgress && pid != m_clientPid)
        {
            // block operation from different comming from
            Serialization::Serialize(send, PC_ERR_DB_CONNECTION);
            return true;
        }
    }

    Try {

    switch (action)
    {
        case LibprivilegeControlAction::APP_ID_FROM_SOCKET: {
            Deserialization::Deserialize(buffer, temp); // sockfd
            LogDebug("sockfd: " << temp);
            char* app_id = perm_app_id_from_socket(temp);

            if (nullptr == app_id) {
                Serialization::Serialize(send, PC_ERR_INVALID_OPERATION);
            } else {
                std::string app_id_str(app_id);
                free(app_id);
                Serialization::Serialize(send, PC_OPERATION_SUCCESS);
                Serialization::Serialize(send, app_id_str);
            }

            break;
        }

        case LibprivilegeControlAction::APP_INSTALL: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            int result = perm_app_install(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::APP_UNINSTALL: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            int result = perm_app_uninstall(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::APP_ENABLE_PERMISSIONS: {
            int persistent;
            std::vector<std::string> permissions;
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, temp);  // app_type
            Deserialization::Deserialize(buffer, persistent);
            Deserialization::Deserialize(buffer, permissions);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_type: " << temp);
            LogDebug("persistent: " << persistent);
            LogDebug("permissions num: " << permissions.size());

            // create null terminated array of strigns
            std::unique_ptr<const char *[]>
            pp_permissions(new (std::nothrow) const char* [permissions.size() + 1]);
            if (nullptr == pp_permissions.get()) {
                LogError("Allocation error!");
                return false;
            }
            for (size_t i = 0; i < permissions.size(); ++i) {
                pp_permissions[i] = permissions[i].c_str();
            }
            pp_permissions[permissions.size()] = nullptr;

            int result = perm_app_enable_permissions(pkg_id.c_str(), static_cast<app_type_t>(temp),
                                                     pp_permissions.get(), persistent);
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::APP_DISABLE_PERMISSIONS: {
            std::vector<std::string> permissions;
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, temp);  // app_type
            Deserialization::Deserialize(buffer, permissions);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("app_type: " << temp);

            // create null terminated array of strigns
            std::unique_ptr<const char *[]>
            pp_permissions(new (std::nothrow) const char* [permissions.size() + 1]);
            if (nullptr == pp_permissions.get()) {
                LogError("Allocation error!");
                return false;
            }
            for (size_t i = 0; i < permissions.size(); ++i) {
                pp_permissions[i] = permissions[i].c_str();
            }
            pp_permissions[permissions.size()] = nullptr;

            int result = perm_app_disable_permissions(pkg_id.c_str(),
                                                      static_cast<app_type_t>(temp),
                                                      pp_permissions.get());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::APP_REVOKE_PERMISSION: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            int result = perm_app_revoke_permissions(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::APP_RESET_PERMISSIONS: {
            Deserialization::Deserialize(buffer, pkg_id);
            LogDebug("pkg_id: " << pkg_id);

            int result = perm_app_reset_permissions(pkg_id.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::APP_SETUP_PATH: {
            std::string pkg_id, path, optional;
            Deserialization::Deserialize(buffer, pkg_id);
            Deserialization::Deserialize(buffer, path);
            Deserialization::Deserialize(buffer, temp); // app path type
            Deserialization::Deserialize(buffer, optional);
            LogDebug("pkg_id: " << pkg_id);
            LogDebug("path: " << path);
            LogDebug("app_path_type: " << temp);
            LogDebug("optional: " << optional);

            int result = perm_app_setup_path(pkg_id.c_str(), path.c_str(),
                                         static_cast<app_path_type_t>(temp), optional.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::APP_ADD_FRIEND: {
            std::string pkg_id1, pkg_id2;
            Deserialization::Deserialize(buffer, pkg_id1);
            Deserialization::Deserialize(buffer, pkg_id2);
            LogDebug("pkg_id1: " << pkg_id1);
            LogDebug("pkg_id2: " << pkg_id2);

            int result = perm_app_add_friend(pkg_id1.c_str(), pkg_id2.c_str());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::ADD_API_FEATURE: {
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

            int result = perm_add_api_feature(static_cast<app_type_t>(temp),
                                              api_feature_name.c_str(),
                                              pp_smack_rules_set.get(),
                                              db_gids.data(), db_gids.size());
            Serialization::Serialize(send, result);
            break;
        }

        case LibprivilegeControlAction::BEGIN: {
            int result = perm_begin();
            Serialization::Serialize(send, result);

            if (PC_OPERATION_SUCCESS == result) {
                m_clientPid = pid;
                m_transactionInProgress = true;
            }
            break;
        }

        case LibprivilegeControlAction::END: {
            int result = perm_end();
            Serialization::Serialize(send, result);

            if (PC_OPERATION_SUCCESS == result) {
                m_transactionInProgress = false;
            }
            break;
        }

        case LibprivilegeControlAction::ROLLBACK: {
            int result = perm_rollback();
            Serialization::Serialize(send, result);

            if (PC_OPERATION_SUCCESS == result) {
                m_transactionInProgress = false;
            }
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

    // update timer every each action requested from the same pid
    m_transactionStart = Clock::now();

    return true;
}

} // namespace SecurityServer
