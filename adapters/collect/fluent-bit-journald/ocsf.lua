-- Open Observability Framework — Fluent Bit Lua Filter -> OCSF v1.3.0 Event Log Activity (1008)
-- Supports Fluent Bit `Time_As_Table On` 5-arg callbacks `(tag, ts, group, metadata, record)`
-- and falls back safely to 3-arg callbacks `(tag, ts, record)`.

local function is_non_empty_string(v)
  return type(v) == "string" and v ~= ""
end

local function first_non_empty(...)
  for i = 1, select("#", ...) do
    local v = select(i, ...)
    if is_non_empty_string(v) then
      return v
    end
  end
  return nil
end

local function parse_uint(v)
  if type(v) == "number" then
    if v >= 0 and v <= 9007199254740991 and math.floor(v) == v then
      return v
    end
    return nil
  end
  if type(v) == "string" and #v >= 1 and #v <= 15 and v:match("^%d+$") then
    return tonumber(v)
  end
  return nil
end

-- Parse microsecond Unix timestamps safely without IEEE-754 precision loss.
local function parse_usec_to_ms_parts(v)
  local s
  if type(v) == "string" then
    s = v
  elseif type(v) == "number" and v > 0 and v <= 9007199254740991 and math.floor(v) == v then
    s = string.format("%.0f", v)
  else
    return nil, nil, nil
  end

  if not s:match("^%d+$") or #s > 18 then
    return nil, nil, nil
  end

  local padded = string.rep("0", math.max(0, 7 - #s)) .. s
  local sec = tonumber(padded:sub(1, #padded - 6))
  local sub_ms = tonumber(padded:sub(#padded - 5, #padded - 3))
  if sec == nil or sec <= 0 then
    return nil, nil, nil
  end
  return sec, sub_ms, sec * 1000 + sub_ms
end

local function format_rfc3339_ms(sec, sub_ms)
  return os.date("!%Y-%m-%dT%H:%M:%S", sec) .. string.format(".%03dZ", sub_ms)
end

local function json_escape_str(s)
  local escaped = s
    :gsub("\\", "\\\\")
    :gsub('"', '\\"')
    :gsub("\b", "\\b")
    :gsub("\f", "\\f")
    :gsub("\n", "\\n")
    :gsub("\r", "\\r")
    :gsub("\t", "\\t")
    :gsub("[%z\1-\31]", function(c)
      return string.format("\\u%04x", string.byte(c))
    end)
  return '"' .. escaped .. '"'
end

local function is_array_table(t)
  local count = 0
  local max_idx = 0
  for k, _ in pairs(t) do
    if type(k) ~= "number" or k <= 0 or math.floor(k) ~= k then
      return false
    end
    count = count + 1
    if k > max_idx then
      max_idx = k
    end
  end
  return count > 0 and max_idx == count
end

local function json_encode(val, depth)
  depth = (depth or 0) + 1
  if depth > 32 then
    return '"[max-depth]"'
  end
  local vt = type(val)
  if vt == "string" then
    return json_escape_str(val)
  elseif vt == "number" then
    if val ~= val or val == math.huge or val == -math.huge then
      return "null"
    end
    return tostring(val)
  elseif vt == "boolean" then
    return val and "true" or "false"
  elseif vt == "table" then
    if next(val) == nil then
      return "{}"
    end
    local parts = {}
    if is_array_table(val) then
      for i = 1, #val do
        parts[#parts + 1] = json_encode(val[i], depth)
      end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      for k, v in pairs(val) do
        parts[#parts + 1] = json_escape_str(tostring(k)) .. ":" .. json_encode(v, depth)
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  end
  return json_escape_str(tostring(val))
end

local function message_to_string(v)
  if v == nil then
    return nil
  end
  if type(v) == "string" then
    return v
  end
  return json_encode(v, 0)
end

local function to_hex(raw)
  local hex = {}
  for i = 1, #raw do
    hex[i] = string.format("%02x", string.byte(raw, i))
  end
  return table.concat(hex)
end

-- Normalize text trace_id / span_id strings (e.g. from journald fields).
local function normalize_text_id(val)
  if type(val) ~= "string" or val == "" then
    return nil
  end
  local clean = val:match("^[0-9a-fA-F]+$") and string.lower(val) or val
  if clean == "" or clean:match("^0+$") then
    return nil
  end
  return clean
end

-- Normalize OTLP trace_id (expected_bytes=16) or span_id (expected_bytes=8).
-- Length distinguishes raw OTLP protobuf binary bytes (16 / 8) from hex strings (32 / 16).
local function normalize_otlp_id(val, expected_bytes)
  if type(val) ~= "string" or val == "" then
    return nil
  end
  local clean
  if #val == expected_bytes then
    clean = to_hex(val)
  elseif #val == expected_bytes * 2 and val:match("^[0-9a-fA-F]+$") then
    clean = string.lower(val)
  else
    if val:find("[^\32-\126]") then
      clean = to_hex(val)
    else
      clean = val:match("^[0-9a-fA-F]+$") and string.lower(val) or val
    end
  end
  if clean == "" or clean:match("^0+$") then
    return nil
  end
  return clean
end

local function map_syslog_severity(priority_val)
  local p = parse_uint(priority_val)
  if p == nil or p > 7 then
    return 0, "Unknown"
  elseif p == 0 then
    return 6, "Fatal"
  elseif p == 1 or p == 2 then
    return 5, "Critical"
  elseif p == 3 then
    return 4, "High"
  elseif p == 4 then
    return 3, "Medium"
  elseif p == 5 then
    return 2, "Low"
  else
    return 1, "Informational"
  end
end

local function map_otlp_severity(severity_number)
  local n = parse_uint(severity_number)
  if n == nil or n == 0 or n > 24 then
    return 0, "Unknown"
  elseif n >= 1 and n <= 12 then
    return 1, "Informational"
  elseif n >= 13 and n <= 16 then
    return 3, "Medium"
  elseif n >= 17 and n <= 20 then
    return 4, "High"
  else
    return 6, "Fatal"
  end
end

local function resolve_ts_parts(ts, fallback_ms)
  if type(ts) == "table" and type(ts.sec) == "number" and ts.sec > 0 then
    local sec = math.floor(ts.sec)
    local nsec = type(ts.nsec) == "number" and math.max(0, math.floor(ts.nsec)) or 0
    local sub_ms = math.floor(nsec / 1000000) % 1000
    local ms = sec * 1000 + sub_ms
    return sec, sub_ms, ms
  end
  if type(fallback_ms) == "number" and fallback_ms > 0 then
    local sec = math.floor(fallback_ms / 1000)
    local sub_ms = math.floor(fallback_ms % 1000)
    return sec, sub_ms, math.floor(fallback_ms)
  end
  local now_sec = os.time()
  return now_sec, 0, now_sec * 1000
end

local JOURNALD_CONSUMED = {
  MESSAGE = true,
  message = true,
  PRIORITY = true,
  SYSLOG_FACILITY = true,
  SYSLOG_IDENTIFIER = true,
  SYSLOG_PID = true,
  _HOSTNAME = true,
  host = true,
  _MACHINE_ID = true,
  _BOOT_ID = true,
  _SYSTEMD_UNIT = true,
  _TRANSPORT = true,
  _PID = true,
  _UID = true,
  _COMM = true,
  _EXE = true,
  _CMDLINE = true,
  __CURSOR = true,
  __REALTIME_TIMESTAMP = true,
  __MONOTONIC_TIMESTAMP = true,
  _SOURCE_REALTIME_TIMESTAMP = true,
  __SOURCE_REALTIME_TIMESTAMP = true,
  TRACE_ID = true,
  OTEL_TRACE_ID = true,
  trace_id = true,
  SPAN_ID = true,
  OTEL_SPAN_ID = true,
  span_id = true,
}

local OTLP_CONSUMED_ATTRS = {
  ["event.id"] = true,
  ["process.pid"] = true,
  ["user.id"] = true,
  ["enduser.id"] = true,
  ["user.name"] = true,
  ["user.full_name"] = true,
}

local OTLP_CONSUMED_RESOURCES = {
  ["host.name"] = true,
  ["service.instance.id"] = true,
  ["host.id"] = true,
  ["os.type"] = true,
  ["process.pid"] = true,
  ["process.executable.name"] = true,
  ["service.name"] = true,
  ["process.executable.path"] = true,
  ["process.command_line"] = true,
}

local function transform_journald(ts, record)
  local rec = type(record) == "table" and record or {}

  local src_sec, src_sub_ms, src_ms = parse_usec_to_ms_parts(rec._SOURCE_REALTIME_TIMESTAMP)
  local rt_sec, rt_sub_ms, rt_ms = parse_usec_to_ms_parts(rec.__REALTIME_TIMESTAMP)

  local sec, sub_ms, time_ms
  if src_ms ~= nil then
    sec, sub_ms, time_ms = src_sec, src_sub_ms, src_ms
  elseif type(ts) == "table" and type(ts.sec) == "number" and ts.sec > 0 then
    sec, sub_ms, time_ms = resolve_ts_parts(ts, nil)
  elseif rt_ms ~= nil then
    sec, sub_ms, time_ms = rt_sec, rt_sub_ms, rt_ms
  else
    sec, sub_ms, time_ms = resolve_ts_parts(ts, nil)
  end

  local logged_ms = rt_ms or (os.time() * 1000)

  local sev_id, sev_label = map_syslog_severity(rec.PRIORITY)
  local raw_prio = nil
  if is_non_empty_string(rec.PRIORITY) then
    raw_prio = rec.PRIORITY
  elseif type(rec.PRIORITY) == "number" and rec.PRIORITY == rec.PRIORITY and rec.PRIORITY ~= math.huge and rec.PRIORITY ~= -math.huge and math.abs(rec.PRIORITY) <= 9007199254740991 and math.floor(rec.PRIORITY) == rec.PRIORITY then
    raw_prio = string.format("%.0f", rec.PRIORITY)
  end

  local systemd_unit = first_non_empty(rec._SYSTEMD_UNIT)
  local syslog_ident = first_non_empty(rec.SYSLOG_IDENTIFIER)
  local transport = first_non_empty(rec._TRANSPORT)
  local comm = first_non_empty(rec._COMM)
  local exe = first_non_empty(rec._EXE)
  local cmdline = first_non_empty(rec._CMDLINE)
  local boot_id = first_non_empty(rec._BOOT_ID)
  local machine_id = first_non_empty(rec._MACHINE_ID)
  local hostname = first_non_empty(rec._HOSTNAME, rec.host)
  local cursor = first_non_empty(rec.__CURSOR)
  local log_name = first_non_empty(systemd_unit, syslog_ident, comm)
  local log_provider = first_non_empty(transport, "systemd-journald")

  local facility = nil
  if is_non_empty_string(rec.SYSLOG_FACILITY) then
    facility = rec.SYSLOG_FACILITY
  elseif type(rec.SYSLOG_FACILITY) == "number" and rec.SYSLOG_FACILITY == rec.SYSLOG_FACILITY and rec.SYSLOG_FACILITY ~= math.huge and rec.SYSLOG_FACILITY ~= -math.huge and math.abs(rec.SYSLOG_FACILITY) <= 9007199254740991 and math.floor(rec.SYSLOG_FACILITY) == rec.SYSLOG_FACILITY then
    facility = string.format("%.0f", rec.SYSLOG_FACILITY)
  end

  local correlation_uid = normalize_text_id(
    first_non_empty(rec.TRACE_ID, rec.OTEL_TRACE_ID, rec.trace_id)
  )
  local span_clean = normalize_text_id(
    first_non_empty(rec.SPAN_ID, rec.OTEL_SPAN_ID, rec.span_id)
  )

  local msg = nil
  if rec.MESSAGE ~= nil then
    msg = message_to_string(rec.MESSAGE)
  elseif rec.message ~= nil then
    msg = message_to_string(rec.message)
  end

  local pid_val = parse_uint(rec._PID)
  if pid_val == nil then
    pid_val = parse_uint(rec.SYSLOG_PID)
  end

  local uid_str = nil
  local uid_num = nil
  if is_non_empty_string(rec._UID) then
    uid_str = rec._UID
    uid_num = parse_uint(rec._UID)
  elseif type(rec._UID) == "number" then
    local parsed_uid = parse_uint(rec._UID)
    if parsed_uid ~= nil then
      uid_str = string.format("%.0f", parsed_uid)
      uid_num = parsed_uid
    end
  end

  local proc = {}
  if pid_val ~= nil then proc.pid = pid_val end
  local proc_name = first_non_empty(comm, syslog_ident)
  if proc_name ~= nil then proc.name = proc_name end
  if exe ~= nil then proc.path = exe end
  if cmdline ~= nil then proc.cmd_line = cmdline end

  local usr = {}
  if uid_str ~= nil then usr.uid = uid_str end
  if uid_num ~= nil then usr.uid_numeric = uid_num end

  local actor = {}
  if next(proc) ~= nil then actor.process = proc end
  if next(usr) ~= nil then actor.user = usr end

  local meta = {
    version = "1.3.0",
    product = {
      name = "Fluent Bit",
      vendor_name = "Chronosphere",
    },
    logged_time = logged_ms,
  }
  if cursor ~= nil then meta.original_event_uid = cursor end
  if correlation_uid ~= nil then meta.correlation_uid = correlation_uid end
  if log_name ~= nil then meta.log_name = log_name end
  if log_provider ~= nil then meta.log_provider = log_provider end
  if raw_prio ~= nil then meta.log_level = raw_prio end
  if facility ~= nil then meta.log_facility = facility end

  local dev = {
    type_id = 1,
    type = "Server",
    os = {
      name = "Linux",
      type_id = 200,
    },
  }
  if hostname ~= nil then dev.hostname = hostname end
  if machine_id ~= nil then
    dev.uid = machine_id
    dev.os_machine_uuid = machine_id
  end
  if boot_id ~= nil then dev.boot_uid = boot_id end

  local unmapped = {}
  for k, v in pairs(rec) do
    if not JOURNALD_CONSUMED[k] then
      unmapped[k] = v
    end
  end
  if span_clean ~= nil then
    unmapped.span_id = span_clean
  end

  local out = {
    category_uid = 1,
    category_name = "System Activity",
    class_uid = 1008,
    class_name = "Event Log Activity",
    type_uid = 100899,
    type_name = "Event Log Activity: Other",
    activity_id = 99,
    activity_name = "Other",
    severity_id = sev_id,
    severity = sev_label,
    time = time_ms,
    time_dt = format_rfc3339_ms(sec, sub_ms),
    metadata = meta,
    device = dev,
  }
  if msg ~= nil then out.message = msg end
  if log_name ~= nil then out.log_name = log_name end
  if log_provider ~= nil then out.log_provider = log_provider end
  if next(actor) ~= nil then out.actor = actor end
  if next(unmapped) ~= nil then out.unmapped = unmapped end
  return out
end

local function transform_otlp(ts, group, metadata, record)
  local rec = type(record) == "table" and record or {}
  local grp = type(group) == "table" and group or {}
  local meta_in = type(metadata) == "table" and metadata or {}
  local otlp = type(meta_in.otlp) == "table" and meta_in.otlp or {}

  local res = (type(grp.resource) == "table" and type(grp.resource.attributes) == "table")
    and grp.resource.attributes or {}
  local scope = type(grp.scope) == "table" and grp.scope or {}

  -- Merge metadata.otlp.attributes and any non-body record fields (defensive across plugin modes)
  local attrs = {}
  if type(otlp.attributes) == "table" then
    for k, v in pairs(otlp.attributes) do
      attrs[k] = v
    end
  end
  for k, v in pairs(rec) do
    if k ~= "body" and k ~= "message" then
      attrs[k] = v
    end
  end

  local obs_ms = nil
  if type(otlp.observed_timestamp) == "number" and otlp.observed_timestamp > 0 then
    obs_ms = math.floor((otlp.observed_timestamp + 200) / 1000000)
  end

  local sec, sub_ms, time_ms = resolve_ts_parts(ts, obs_ms)
  local logged_ms = (obs_ms ~= nil and obs_ms > 0) and obs_ms or (os.time() * 1000)

  local sev_id, sev_label = map_otlp_severity(otlp.severity_number)
  local sev_text = is_non_empty_string(otlp.severity_text) and otlp.severity_text or nil

  local scope_name = first_non_empty(scope.name)
  local service_name = first_non_empty(res["service.name"])
  local log_name = first_non_empty(scope_name, service_name)
  local log_provider = "opentelemetry"

  local msg = nil
  if rec.body ~= nil then
    msg = message_to_string(rec.body)
  elseif rec.message ~= nil then
    msg = message_to_string(rec.message)
  end

  local correlation_uid = normalize_otlp_id(otlp.trace_id, 16)
  local span_clean = normalize_otlp_id(otlp.span_id, 8)
  local event_uid = first_non_empty(attrs["event.id"], span_clean)

  local hostname = first_non_empty(res["host.name"], res["service.instance.id"])
  local host_id = first_non_empty(res["host.id"])

  local dev_os = nil
  if is_non_empty_string(res["os.type"]) then
    local os_lc = string.lower(res["os.type"])
    if os_lc == "linux" then
      dev_os = { name = "Linux", type_id = 200 }
    elseif os_lc == "windows" then
      dev_os = { name = "Windows", type_id = 100 }
    elseif os_lc == "darwin" or os_lc == "macos" then
      dev_os = { name = "macOS", type_id = 300 }
    end
  end

  local pid_val = parse_uint(res["process.pid"])
  if pid_val == nil then
    pid_val = parse_uint(attrs["process.pid"])
  end

  local proc = {}
  if pid_val ~= nil then proc.pid = pid_val end
  local proc_name = first_non_empty(res["process.executable.name"], service_name)
  if proc_name ~= nil then proc.name = proc_name end
  local proc_path = first_non_empty(res["process.executable.path"])
  if proc_path ~= nil then proc.path = proc_path end
  local proc_cmd = first_non_empty(res["process.command_line"])
  if proc_cmd ~= nil then proc.cmd_line = proc_cmd end

  local raw_uid = attrs["user.id"] ~= nil and attrs["user.id"] or attrs["enduser.id"]
  local uid_str = nil
  local uid_num = nil
  if is_non_empty_string(raw_uid) then
    uid_str = raw_uid
    uid_num = parse_uint(raw_uid)
  elseif type(raw_uid) == "number" and raw_uid >= 0 and raw_uid <= 9007199254740991 and math.floor(raw_uid) == raw_uid then
    uid_str = string.format("%.0f", raw_uid)
    uid_num = raw_uid
  end
  local user_name = first_non_empty(attrs["user.name"], attrs["user.full_name"])

  local usr = {}
  if uid_str ~= nil then usr.uid = uid_str end
  if uid_num ~= nil then usr.uid_numeric = uid_num end
  if user_name ~= nil then usr.name = user_name end

  local actor = {}
  if next(proc) ~= nil then actor.process = proc end
  if next(usr) ~= nil then actor.user = usr end

  local meta = {
    version = "1.3.0",
    product = {
      name = "Fluent Bit",
      vendor_name = "Chronosphere",
    },
    logged_time = logged_ms,
  }
  if event_uid ~= nil then meta.original_event_uid = event_uid end
  if correlation_uid ~= nil then meta.correlation_uid = correlation_uid end
  if log_name ~= nil then meta.log_name = log_name end
  meta.log_provider = log_provider
  if sev_text ~= nil then meta.log_level = sev_text end

  local dev = {
    type_id = 0,
    type = "Unknown",
  }
  if hostname ~= nil then dev.hostname = hostname end
  if host_id ~= nil then dev.uid = host_id end
  if dev_os ~= nil then dev.os = dev_os end

  local unmapped_attrs = {}
  for k, v in pairs(attrs) do
    if not OTLP_CONSUMED_ATTRS[k] then
      unmapped_attrs[k] = v
    end
  end

  local unmapped_res = {}
  for k, v in pairs(res) do
    if not OTLP_CONSUMED_RESOURCES[k] then
      unmapped_res[k] = v
    end
  end

  local unmapped = {}
  if next(unmapped_attrs) ~= nil then unmapped.attributes = unmapped_attrs end
  if next(unmapped_res) ~= nil then unmapped.resource = unmapped_res end
  if span_clean ~= nil then unmapped.span_id = span_clean end
  if type(otlp.dropped_attributes_count) == "number" and otlp.dropped_attributes_count > 0 then
    unmapped.dropped_attributes_count = otlp.dropped_attributes_count
  end

  local out = {
    category_uid = 1,
    category_name = "System Activity",
    class_uid = 1008,
    class_name = "Event Log Activity",
    type_uid = 100899,
    type_name = "Event Log Activity: Other",
    activity_id = 99,
    activity_name = "Other",
    severity_id = sev_id,
    severity = sev_label,
    time = time_ms,
    time_dt = format_rfc3339_ms(sec, sub_ms),
    metadata = meta,
    device = dev,
  }
  if msg ~= nil then out.message = msg end
  if log_name ~= nil then out.log_name = log_name end
  out.log_provider = log_provider
  if next(actor) ~= nil then out.actor = actor end
  if next(unmapped) ~= nil then out.unmapped = unmapped end
  return out
end

function to_ocsf(tag, ts, group, metadata, record)
  -- Explicit 5-parameter signature (nparams == 5) is required by Fluent Bit filter_lua
  -- to invoke 5-arg mode with OTLP group & metadata; also supports standalone 3-arg calls.
  local three_arg = (record == nil and metadata == nil and type(group) == "table")
  if three_arg then
    record = group
    group = nil
  end

  local is_otlp = (type(tag) == "string" and tag:find("otlp", 1, true) ~= nil)
    or (type(metadata) == "table" and type(metadata.otlp) == "table")

  local out
  if is_otlp then
    out = transform_otlp(ts, group, metadata, record)
  else
    out = transform_journald(ts, record)
  end

  if three_arg then
    return 1, ts, out
  end
  return 1, ts, {}, out
end
