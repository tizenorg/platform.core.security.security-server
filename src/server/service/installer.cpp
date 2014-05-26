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

#include <sys/stat.h>
#include <sys/smack.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <memory>
#include <fts.h>

#include "installer.h"
#include "protocols.h"
#include "security-server.h"
#include "security-manager.h"
#include "security-manager-common.h"

namespace SecurityServer {

namespace {

const InterfaceID INSTALLER_IFACE = 0;

/* Const defined below is used to label links to executables */
const char *XATTR_NAME_TIZENEXEC =  XATTR_SECURITY_PREFIX "TIZEN_EXEC_LABEL";

/**
 * Return values
 * -1 - error
 * 0 - skip
 * 1 - label
 */
enum class FileDecision {
    SKIP = 0,
    LABEL = 1,
    ERROR = -1
};
typedef FileDecision (*labelDecisionFn)(const FTSENT*);



static FileDecision labelAll(const FTSENT *ftsent __attribute__((unused)))
{
    LogSecureDebug("Entering function: " << __func__);

    return FileDecision::LABEL;
}

static FileDecision labelDirs(const FTSENT *ftsent)
{
    LogSecureDebug("Entering function: " << __func__);

    // label only directories
    if (S_ISDIR(ftsent->fts_statp->st_mode))
        return FileDecision::LABEL;
    return FileDecision::SKIP;
}

static FileDecision labelExecs(const FTSENT *ftsent)
{
    LogSecureDebug("Entering function: " << __func__);

    LogDebug("Mode = " << ftsent->fts_statp->st_mode);
    // label only regular executable files
    if (S_ISREG(ftsent->fts_statp->st_mode) && (ftsent->fts_statp->st_mode & S_IXUSR))
        return FileDecision::LABEL;
    return FileDecision::SKIP;
}


static FileDecision labelLinksToExecs(const FTSENT *ftsent)
{
    LogSecureDebug("Entering function: " << __func__);

    struct stat buf;
    char *target;

    // check if it's a link
    if ( !S_ISLNK(ftsent->fts_statp->st_mode))
        return FileDecision::SKIP;

    target = realpath(ftsent->fts_path, NULL);
    if (!target) {
        LogSecureError("Getting link target for " << ftsent->fts_path << " failed (Error = " << strerror(errno) << ")");
        return FileDecision::ERROR;
    }
    if (-1 == stat(target, &buf)) {
        LogSecureError("stat failed for " << target << " (Error = " << strerror(errno) << ")");
        return FileDecision::ERROR;
    }
    // skip if link target is not a regular executable file
    if (buf.st_mode != (buf.st_mode | S_IXUSR | S_IFREG)) {
        LogSecureDebug(target << "is not a regular executable file. Skipping.");
        return FileDecision::SKIP;
    }

    return FileDecision::LABEL;
}

static bool dirSetSmack(const std::string &path, const std::string &label,
        const char *xattr_name, labelDecisionFn fn)
{
    LogSecureDebug("Entering function: "<< __func__ <<". Params:"
            " path=" << path << ", label=" << label << ", xattr=" << xattr_name);


    const char *path_argv[] = {path.c_str(), NULL};
    FTSENT *ftsent;
    FileDecision ret;

    std::unique_ptr<FTS, std::function<void(FTS*)> > fts(
            fts_open((char * const *) path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL),
            fts_close);

    if (fts.get() == NULL) {
        LogError("fts_open failed.");
        return false;
    }

    while ((ftsent = fts_read(fts.get())) != NULL) {
        /* Check for error (FTS_ERR) or failed stat(2) (FTS_NS) */
        if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
            LogError("FTS_ERR error or failed stat(2) (FTS_NS)");
            return false;
        }

        ret = fn(ftsent);
        if (ret == FileDecision::ERROR) {
            LogError("fn(ftsent) failed.");
            return false;
        }

        if (ret == FileDecision::LABEL) {
            if (lsetxattr(ftsent->fts_path, xattr_name, label.c_str(), label.length(), 0) != 0) {
                LogError("smack_lsetlabel failed.");
                return false;
            }
        }

    }

    /* If last call to fts_read() set errno, we need to return error. */
    if ((errno != 0) && (ftsent == NULL)) {
        LogError("Last errno from fts_read: " << strerror(errno));
        return false;
    }
    return true;
}


static bool labelDir(const std::string &path, const std::string &label,
        bool set_transmutable, bool set_executables)
{
    LogSecureDebug("Entering function: "<< __func__ <<". Params:"
            " path=" << path << " label= " << label
            << " set_transmutable= " << set_transmutable
            << " set_executables= " << set_executables);
    bool ret = true;

    // setting access label on everything in given directory and below
    ret = dirSetSmack(path, label, XATTR_NAME_SMACK, labelAll);
    if (!ret) {
        LogError("dir_set_smack failed (access label)");
        return ret;
    }

    if (set_transmutable) {
        // setting transmute on dirs
        ret = dirSetSmack(path, "TRUE", XATTR_NAME_SMACKTRANSMUTE, labelDirs);
        if (!ret) {
            LogError("dir_set_smack failed (transmute)");
            return ret;
        }
    }

    if (set_executables) {
        ret = dirSetSmack(path, label, XATTR_NAME_SMACKEXEC, &labelExecs);
        if (!ret)
        {
            LogError("dir_set_smack failed (execs).");
            return ret;
        }

        //setting execute label for everything with permission to execute
        ret = dirSetSmack(path, label, XATTR_NAME_TIZENEXEC, &labelLinksToExecs);
        if (!ret)
        {
            LogError("dir_set_smack failed (link to execs).");
            return ret;
        }
    }

    return ret;
}


bool setupPath(const std::string &pkgId, const std::pair<std::string, int> &appPath)
{
    using namespace SecurityManager;

    app_install_path_type pathType = static_cast<app_install_path_type>(appPath.second);
    std::string label;
    bool label_executables, label_transmute;


    switch (pathType) {
    case SECURITY_MANAGER_PATH_PRIVATE:
        if(!generateAppLabel(pkgId,label))
            return false;
        label_executables = true;
        label_transmute = false;
        break;
    case SECURITY_MANAGER_PATH_PUBLIC:
        label.assign(InstallerService::LABEL_FOR_PUBLIC_APP_PATH);
        label_executables = false;
        label_transmute = true;
        break;
    case SECURITY_MANAGER_PATH_PUBLIC_RO:
        label.assign("_");
        label_executables = false;
        label_transmute = false;
        break;
    default:
        LogError("Path type not known.");
        return false;
    }
    if (!labelDir(appPath.first, label, label_transmute, label_executables))
        return false;
    else return true;
}

} // namespace anonymous

/* Const defined below is used to label links to executables */
const char *InstallerService::LABEL_FOR_PUBLIC_APP_PATH = "User";

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
        result = setupPath(req.pkgId, appPath);
        if (!result) {
            LogDebug("setupPath() failed ");
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

    // success
    Serialization::Serialize(send, SECURITY_SERVER_API_SUCCESS);
    return true;
}

} // namespace SecurityServer
