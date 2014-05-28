/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bartlomiej Grzelewski <b.grzelewski@samsung.com>
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
 * @file        installer.cpp
 * @author      Michal Witanowski (m.witanowski@samsung.com)
 * @brief       Implementation of installer service for libprivilege-control encapsulation.
 */

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <privilege-control.h>
#include "installer.h"
#include "protocols.h"
#include "security-server.h"
#include "security-manager.h"
#include "security-manager-common.h"

namespace SecurityServer {

namespace {

const InterfaceID INSTALLER_IFACE = 0;

/**
 * Convert Security Mangager's API path type to libprivilege-control's API path type.
 * @return true on success
 */
bool TranslateAppPathType(const app_install_path_type path_type,
                          app_path_type_t& lpc_path_type)
{
    switch (path_type) {
        case SECURITY_MANAGER_PATH_PRIVATE:
            lpc_path_type = APP_PATH_PRIVATE;
            break;
        case SECURITY_MANAGER_PATH_PUBLIC:
            lpc_path_type = APP_PATH_PUBLIC;
            break;
        case SECURITY_MANAGER_PATH_PUBLIC_RO:
            lpc_path_type = APP_PATH_FLOOR;
            break;
        default:
            return false;
    };
    return true;
}

} // namespace anonymous


InstallerService::InstallerService()
{
}

GenericSocketService::ServiceDescriptionVector InstallerService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_INSTALLER, "security-server::installer", INSTALLER_IFACE},
    };
}

void InstallerService::accept(const AcceptEvent &event)
{
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock <<
             " ConnectionID.counter: " << event.connectionID.counter <<
             " ServiceID: " << event.interfaceID);

    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void InstallerService::write(const WriteEvent &event)
{
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
             " Size: " << event.size <<
             " Left: " << event.left);

    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void InstallerService::process(const ReadEvent &event)
{
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while (processOne(event.connectionID, info.buffer, info.interfaceID));
}

void InstallerService::close(const CloseEvent &event)
{
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

bool InstallerService::processOne(const ConnectionID &conn, MessageBuffer &buffer,
                                  InterfaceID interfaceID)
{
    LogDebug("Iteration begin. Interface = " << interfaceID);

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    MessageBuffer send;
    bool retval = false;

    if (INSTALLER_IFACE == interfaceID) {
        Try {
            // deserialize API call type
            int call_type_int;
            Deserialization::Deserialize(buffer, call_type_int);
            SecurityModuleCall call_type = static_cast<SecurityModuleCall>(call_type_int);

            switch (call_type) {
                case SecurityModuleCall::APP_INSTALL:
                    processAppInstall(buffer, send);
                    break;
                case SecurityModuleCall::APP_UNINSTALL:
                    processAppUninstall(buffer, send);
                    break;
                default:
                    LogError("Invalid call: " << call_type_int);
                    Throw(InstallerException::InvalidAction);
            }
            // if we reach this point, the protocol is OK
            retval = true;
        } Catch (MessageBuffer::Exception::Base) {
            LogError("Broken protocol.");
        } Catch (InstallerException::Base) {
            LogError("Broken protocol.");
        } catch (std::exception &e) {
            LogError("STD exception " << e.what());
        } catch (...) {
            LogError("Unknown exception");
        }
    }
    else {
        LogError("Wrong interface");
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

bool InstallerService::processAppInstall(MessageBuffer &buffer, MessageBuffer &send)
{
    // deserialize request data
    app_inst_req req;
    Deserialization::Deserialize(buffer, req.appId);
    Deserialization::Deserialize(buffer, req.pkgId);
    Deserialization::Deserialize(buffer, req.allowedUsers);
    Deserialization::Deserialize(buffer, req.privileges);
    Deserialization::Deserialize(buffer, req.appPaths);

    LogDebug("appId: " << req.appId);
    LogDebug("pkgId: " << req.pkgId);

    // create null terminated array of strigns for permissions
    std::unique_ptr<const char *[]> pp_permissions(new const char* [req.privileges.size() + 1]);
    for (size_t i = 0; i < req.privileges.size(); ++i) {
        LogDebug("Permission = " << req.privileges[i]);
        pp_permissions[i] = req.privileges[i].c_str();
    }
    pp_permissions[req.privileges.size()] = nullptr;

    // start database transaction
    int result = perm_begin();
    LogDebug("perm_begin() returned " << result);
    if (PC_OPERATION_SUCCESS != result) {
        // libprivilege is locked
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SERVER_ERROR);
        return false;
    }

    /**
     * TODO: use pkgId.
     * This is a temporary solution: perm_app_* requires pkgId. We assume that pkgId == appId.
     */
    result = perm_app_install(req.appId.c_str());
    LogDebug("perm_app_install() returned " << result);
    if (PC_OPERATION_SUCCESS != result) {
        // libprivilege error
        goto error_label;
    }

    // TODO: use pkgId.
    result = perm_app_enable_permissions(req.appId.c_str(), APP_TYPE_WGT,
                                         pp_permissions.get(), true);
    LogDebug("perm_app_enable_permissions() returned " << result);
    if (PC_OPERATION_SUCCESS != result) {
        // libprivilege error
        goto error_label;
    }

    // register paths
    for (const auto& appPath : req.appPaths) {
        app_path_type_t path_type;
        if (!TranslateAppPathType((app_install_path_type)appPath.second,
                                  path_type)) {
            LogError("Unrecognized path type: " << appPath.second);
            goto error_label;
        }
        LogDebug("Adding path: " << appPath.first << " (type " << path_type << ")");

        // TODO: use pkgId.
        result = perm_app_setup_path(req.appId.c_str(), appPath.first.c_str(), path_type);
        if (PC_OPERATION_SUCCESS != result) {
            // libprivilege error
            LogDebug("perm_app_setup_path() returned " << result);
            goto error_label;
        }
    }

    // finish database transaction
    result = perm_end();
    LogDebug("perm_end() returned " << result);
    if (PC_OPERATION_SUCCESS != result) {
        // error in libprivilege-control
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SERVER_ERROR);
        return false;
    }

    // TODO: This should be done only for the first application in the package
    if (!SecurityManager::installPackageSmackRules(req.pkgId)) {
        LogError("Failed to apply package-specific smack rules");
        goto error_label;
    }

    // success
    Serialization::Serialize(send, SECURITY_SERVER_API_SUCCESS);
    return true;

error_label:
    // rollback failed transaction before exiting
    result = perm_rollback();
    LogDebug("perm_rollback() returned " << result);
    Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SERVER_ERROR);
    return false;
}

bool InstallerService::processAppUninstall(MessageBuffer &buffer, MessageBuffer &send)
{
    // deserialize request data
    std::string appId;
    Deserialization::Deserialize(buffer, appId);
    LogDebug("appId: " << appId);

    int result = perm_begin();
    LogDebug("perm_begin() returned " << result);
    if (PC_OPERATION_SUCCESS != result) {
        // libprivilege is locked
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SERVER_ERROR);
        return false;
    }

    // TODO: use pkgId.
    result = perm_app_uninstall(appId.c_str());
    LogDebug("perm_app_uninstall() returned " << result);

    if (PC_OPERATION_SUCCESS != result) {
        // error in libprivilege-control
        result = perm_rollback();
        LogDebug("perm_rollback() returned " << result);
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SERVER_ERROR);
        return false;
    }

    // finish database transaction
    result = perm_end();
    LogDebug("perm_end() returned " << result);
    if (PC_OPERATION_SUCCESS != result) {
        // error in libprivilege-control
        Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SERVER_ERROR);
        return false;
    }

    // TODO: Uncomment once proper pkgId -> smack label mapping is implemented (currently all applications are mapped
    //       to user label and removal of such rules would be harmful)
    // TODO: This should be performed only for the last application in the package
    // TODO: retrieve pkgId as it's not available in the request
    //if (!SecurityManager::uninstallPackageSmackRules(appId)) {
    //    LogError("Error on uninstallation of package-specific smack rules");
    //    Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_SERVER_ERROR);
    //    return false;
    //}

    // success
    Serialization::Serialize(send, SECURITY_SERVER_API_SUCCESS);
    return true;
}

} // namespace SecurityServer
