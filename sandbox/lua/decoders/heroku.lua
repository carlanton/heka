-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

local syslog = require "syslog"

local template = "%iut% <%pri%>%protocol-version% %TIMESTAMP:::date-rfc3339% %HOSTNAME% %app-name% %procid% %msgid%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%"

local msg = {
Timestamp   = nil,
Type        = "HerokuLog",
Hostname    = nil,
Payload     = nil,
Pid         = nil,
Severity    = nil,
Fields      = nil
}

local grammar = syslog.build_rsyslog_grammar(template)

function process_message ()
    local log = read_message("Payload")
    local fields = grammar:match(log)
    if not fields then return -1 end

    if fields.timestamp then
        msg.Timestamp = fields.timestamp
    end

    local syslogfacility = nil
    if fields.pri then
        msg.Severity = fields.pri.severity
        syslogfacility = fields.pri.facility
    end

    msg.Hostname = string.sub(read_message("Fields[Path]"), 2)
    msg.Payload = fields.msg

    msg.Fields = {
        dyno = fields["procid"],
        source = fields["app-name"],
        drainToken = read_message("Fields[Logplex-Drain-Token]"),
        logplexVersion = read_message("Fields[UserAgent]"),
        syslogfacility = syslogfacility
    }

    inject_message(msg)
    return 0
end
