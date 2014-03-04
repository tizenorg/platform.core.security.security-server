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
 * @file        privilege.h
 * @author      Michal Witanowski (m.witanowski@samsung.com)
 * @brief       Implementation of service encapsulating libprivilege-control.
 */

#ifndef _SECURITY_SERVER_PRIVILEGE_CONTROL_
#define _SECURITY_SERVER_PRIVILEGE_CONTROL_

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <dpl/serialization.h>
#include <message-buffer.h>
#include <connection-info.h>
#include <chrono>

namespace SecurityServer {

enum class LibprivilegeControlAction;

class PrivilegeControlSevice  :
    public SecurityServer::GenericSocketService
  , public SecurityServer::ServiceThread<PrivilegeControlSevice>
{
public:
    PrivilegeControlSevice();
    ServiceDescriptionVector GetServiceDescription();

    DECLARE_THREAD_EVENT(AcceptEvent, accept)
    DECLARE_THREAD_EVENT(WriteEvent, write)
    DECLARE_THREAD_EVENT(ReadEvent, process)
    DECLARE_THREAD_EVENT(CloseEvent, close)

    void accept(const AcceptEvent &event);
    void write(const WriteEvent &event);
    void process(const ReadEvent &event);
    void close(const CloseEvent &event);

private:
    typedef std::chrono::duration<int, std::milli> Millisecs;
    typedef std::chrono::system_clock Clock;

    Clock::time_point m_transactionStart;
    pid_t m_clientPid;
    bool m_transactionInProgress; // are we in perm_begin() perm_end() block?
    ConnectionInfoMap m_connectionInfoMap;

    bool processAction(MessageBuffer &buffer, MessageBuffer &send);
    bool processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID);
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_PRIVILEGE_CONTROL_
