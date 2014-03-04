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
const SecurityServer::InterfaceID PRIVILEGE_CONTROL_IFACE = 0;

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
        {SERVICE_SOCKET_LIBPRIVILEGE_CONTROL,
         "security-server::libprivilege-control",
         PRIVILEGE_CONTROL_IFACE},
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

    // extract client's PID from the socket
    struct ucred credentials;
    unsigned int cr_len = sizeof(credentials);
    if (0 != getsockopt(conn.sock, SOL_SOCKET, SO_PEERCRED, &credentials, &cr_len)) {
        LogError("getsockopt() failed: " << strerror(errno));
        return false;
    }

    MessageBuffer send;
    bool retval = false;
    if (interfaceID != PRIVILEGE_CONTROL_IFACE) {
        LogError("Wrong interface");
    } else {
        retval = processAction(buffer, send, credentials.pid);
    }

    if (retval) {
        //send response
        m_serviceManager->Write(conn, send.Pop());
    } else {
        LogError("Closing socket because of error");
        m_serviceManager->Close(conn);
    }

    return retval;
}

/**
 * Convert libprivilege-control API error code (PC_*) into Security Server code (SECURITY_SERVER_*)
 */
int PrivilegeControlSevice::toSecurityServerError(int libprivilegeControlErrorCode)
{
    switch (libprivilegeControlErrorCode) {
        case PC_OPERATION_SUCCESS:      return SECURITY_SERVER_API_SUCCESS;
        case PC_ERR_FILE_OPERATION:     return SECURITY_SERVER_API_ERROR_FILE_OPERATION;
        case PC_ERR_MEM_OPERATION:      return SECURITY_SERVER_API_ERROR_MEM_OPERATION;
        case PC_ERR_NOT_PERMITTED:      return SECURITY_SERVER_API_ERROR_NOT_PERMITTED;
        case PC_ERR_INVALID_PARAM:      return SECURITY_SERVER_API_ERROR_INVALID_PARAM;
        case PC_ERR_INVALID_OPERATION:  return SECURITY_SERVER_API_ERROR_INVALID_OPERATION;
        case PC_ERR_DB_OPERATION:       return SECURITY_SERVER_API_ERROR_DB_OPERATION;
        case PC_ERR_DB_LABEL_TAKEN:     return SECURITY_SERVER_API_ERROR_DB_LABEL_TAKEN;
        case PC_ERR_DB_QUERY_PREP:      return SECURITY_SERVER_API_ERROR_DB_QUERY_PREP;
        case PC_ERR_DB_QUERY_BIND:      return SECURITY_SERVER_API_ERROR_DB_QUERY_BIND;
        case PC_ERR_DB_QUERY_STEP:      return SECURITY_SERVER_API_ERROR_DB_QUERY_STEP;
        case PC_ERR_DB_CONNECTION:      return SECURITY_SERVER_API_ERROR_DB_CONNECTION;
        case PC_ERR_DB_NO_SUCH_APP:     return SECURITY_SERVER_API_ERROR_DB_NO_SUCH_APP;
        case PC_ERR_DB_PERM_FORBIDDEN:  return SECURITY_SERVER_API_ERROR_DB_PERM_FORBIDDEN;
        default:                        return SECURITY_SERVER_API_ERROR_UNKNOWN;
    }
}

bool PrivilegeControlSevice::processAction(MessageBuffer &buffer, MessageBuffer &send, pid_t pid)
{
    // deserialize client pid
    pid_t received_pid;
    Deserialization::Deserialize(buffer, received_pid);

    // verify received PID
    if (received_pid != pid) {
        LogError("PID mismatch: " << received_pid << " received, should be " << pid);
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_NOT_PERMITTED);
        return false;
    }

    // deserialize libprivilege-control action code
    int action_int;
    Deserialization::Deserialize(buffer, action_int);
    auto action = static_cast<LibprivilegeControlAction>(action_int);

    if (m_transactionInProgress) {
        // measure time since last action
        Millisecs duration(
            std::chrono::duration_cast<Millisecs>(Clock::now() - m_transactionStart));

        // timeout exceeded
        if (duration.count() > TRANSACTION_TIMEOUT) {
            perm_rollback();
            m_transactionInProgress = false;
        }
    }

    // block any operation comming from a different PID
    if (m_transactionInProgress && pid != m_clientPid) {
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SIMULTANEOUS_ACCESS);
        return true;
    }

    // update timer every each action requested from the same PID
    m_transactionStart = Clock::now();

    Try {

    switch (action)
    {
    case LibprivilegeControlAction::APP_INSTALL:
        processAppInstall(buffer, send);
        break;

    case LibprivilegeControlAction::APP_UNINSTALL:
        processAppUninstall(buffer, send);
        break;

    case LibprivilegeControlAction::APP_ENABLE_PERMISSIONS:
        processAppEnablePermissions(buffer, send);
        break;

    case LibprivilegeControlAction::APP_DISABLE_PERMISSIONS:
        processAppDisablePermissions(buffer, send);
        break;

    case LibprivilegeControlAction::APP_REVOKE_PERMISSIONS:
        processAppRevokePermissions(buffer, send);
        break;

    case LibprivilegeControlAction::APP_RESET_PERMISSIONS:
        processAppResetPermissions(buffer, send);
        break;

    case LibprivilegeControlAction::APP_SETUP_PATH:
        processAppSetupPath(buffer, send);
        break;

    case LibprivilegeControlAction::ADD_API_FEATURE:
        processAddApiFeature(buffer, send);
        break;

    case LibprivilegeControlAction::BEGIN:
        if (processPermBegin(send)) {
            m_clientPid = pid;
            m_transactionInProgress = true;
        }
        break;

    case LibprivilegeControlAction::END:
        if (processPermEnd(send)) {
            m_transactionInProgress = false;
        }
        break;

    case LibprivilegeControlAction::ROLLBACK:
        if (processPermRollback(send)) {
            m_transactionInProgress = false;
        }
        break;

    default:
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_BAD_REQUEST);
        LogError("Invalid libprivilege-control action code (" << action_int << ")");
        return false;
    }

    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    } catch (std::exception &e) {
        LogError("STD exception " << e.what());
    }

    return true;
}

void PrivilegeControlSevice::processAppInstall(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string pkg_id;
    Deserialization::Deserialize(buffer, pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    int result = perm_app_install(pkg_id.c_str());
    LogDebug("perm_app_install() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

void PrivilegeControlSevice::processAppUninstall(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string pkg_id;
    Deserialization::Deserialize(buffer, pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    int result = perm_app_uninstall(pkg_id.c_str());
    LogDebug("perm_app_uninstall() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

void PrivilegeControlSevice::processAppEnablePermissions(MessageBuffer &buffer,
                                                         MessageBuffer &send)
{
    std::string pkg_id;
    int persistent, app_type;
    std::vector<std::string> permissions;
    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, persistent);
    Deserialization::Deserialize(buffer, permissions);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("app_type: " << app_type);
    LogDebug("persistent: " << persistent);
    LogDebug("permissions num: " << permissions.size());

    // create null terminated array of strigns
    std::unique_ptr<const char *[]>
        pp_permissions(new const char* [permissions.size() + 1]);

    for (size_t i = 0; i < permissions.size(); ++i) {
        pp_permissions[i] = permissions[i].c_str();
    }
    pp_permissions[permissions.size()] = nullptr;

    int result = perm_app_enable_permissions(pkg_id.c_str(), static_cast<app_type_t>(app_type),
                                             pp_permissions.get(), persistent);
    LogDebug("perm_app_enable_permissions() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

void PrivilegeControlSevice::processAppDisablePermissions(MessageBuffer &buffer,
                                                          MessageBuffer &send)
{
    std::string pkg_id;
    int app_type;
    std::vector<std::string> permissions;
    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, permissions);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("app_type: " << app_type);

    // create null terminated array of strigns
    std::unique_ptr<const char *[]>
        pp_permissions(new const char* [permissions.size() + 1]);

    for (size_t i = 0; i < permissions.size(); ++i) {
        pp_permissions[i] = permissions[i].c_str();
    }
    pp_permissions[permissions.size()] = nullptr;

    int result = perm_app_disable_permissions(pkg_id.c_str(), static_cast<app_type_t>(app_type),
                                              pp_permissions.get());
    LogDebug("perm_app_disable_permissions() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

void PrivilegeControlSevice::processAppRevokePermissions(MessageBuffer &buffer,
                                                         MessageBuffer &send)
{
    std::string pkg_id;
    Deserialization::Deserialize(buffer, pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    int result = perm_app_revoke_permissions(pkg_id.c_str());
    LogDebug("perm_app_revoke_permissions() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

void PrivilegeControlSevice::processAppResetPermissions(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string pkg_id;
    Deserialization::Deserialize(buffer, pkg_id);
    LogDebug("pkg_id: " << pkg_id);

    int result = perm_app_reset_permissions(pkg_id.c_str());
    LogDebug("perm_app_reset_permissions() returned" << result);
    result = toSecurityServerError(result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

void PrivilegeControlSevice::processAppSetupPath(MessageBuffer &buffer, MessageBuffer &send)
{
    std::string pkg_id, path, optional;
    int app_path_type;
    Deserialization::Deserialize(buffer, pkg_id);
    Deserialization::Deserialize(buffer, path);
    Deserialization::Deserialize(buffer, app_path_type);
    Deserialization::Deserialize(buffer, optional);
    LogDebug("pkg_id: " << pkg_id);
    LogDebug("path: " << path);
    LogDebug("app_path_type: " << app_path_type);
    LogDebug("optional: " << optional);

    int result = perm_app_setup_path(pkg_id.c_str(), path.c_str(),
                                 static_cast<app_path_type_t>(app_path_type), optional.c_str());
    LogDebug("perm_app_setup_path() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

void PrivilegeControlSevice::processAddApiFeature(MessageBuffer &buffer, MessageBuffer &send)
{
    int app_type;
    std::string api_feature_name;
    std::vector<std::string> smack_rules_set;
    std::vector<unsigned int> db_gids;
    Deserialization::Deserialize(buffer, app_type);
    Deserialization::Deserialize(buffer, api_feature_name);
    Deserialization::Deserialize(buffer, smack_rules_set);
    Deserialization::Deserialize(buffer, db_gids);
    LogDebug("app_type: " << app_type);
    LogDebug("api_feature_name: " << api_feature_name);

    // create null terminated array of strigns
    std::unique_ptr<const char *[]>
        pp_smack_rules_set(new const char* [smack_rules_set.size() + 1]);

    for (size_t i = 0; i < smack_rules_set.size(); ++i) {
        pp_smack_rules_set[i] = smack_rules_set[i].c_str();
    }
    pp_smack_rules_set[smack_rules_set.size()] = nullptr;

    int result = perm_add_api_feature(static_cast<app_type_t>(app_type),
                                      api_feature_name.c_str(), pp_smack_rules_set.get(),
                                      db_gids.data(), db_gids.size());
    LogDebug("perm_add_api_feature() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
}

bool PrivilegeControlSevice::processPermBegin(MessageBuffer &send)
{
    int result = perm_begin();
    LogDebug("perm_begin() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
    return (PC_OPERATION_SUCCESS == result);
}

bool PrivilegeControlSevice::processPermEnd(MessageBuffer &send)
{
    int result = perm_end();
    LogDebug("perm_end() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
    return (PC_OPERATION_SUCCESS == result);
}

bool PrivilegeControlSevice::processPermRollback(MessageBuffer &send)
{
    int result = perm_rollback();
    LogDebug("perm_rollback() returned" << result);
    Serialization::Serialize(send, toSecurityServerError(result));
    return (PC_OPERATION_SUCCESS == result);
}

} // namespace SecurityServer
