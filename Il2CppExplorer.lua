-- https://github.com/HTCheater/Il2CppExplorer truonggiangsualai
if (explorer == nil or type(explorer) ~= 'table') then
	explorer = {}
end
-- Output debug messages
if explorer.debug == nil then
	explorer.debug = false
end
-- Let people know you are using my framework :D
if (explorer.printAdvert == nil) then
	explorer.printAdvert = true
end
-- Exit if selected process isn't Unity game
if (explorer.exitOnNotUnityGame == nil) then
	explorer.exitOnNotUnityGame = true
end
-- Contains start address of libil2cpp.so once either explorer.getLib or explorer.patchLib or explorer.editFunction was called
local libStart = 0x0
explorer.maxStringLength = 1000
local alphabet = {}

if explorer.printAdvert then
	print('✨ Made with Il2CppExplorer by HTCheater')
end

if (explorer.exitOnNotUnityGame and #gg.getRangesList('global-metadata.dat') < 1) then
	print('🔴 Please, select Unity game')
	os.exit()
end

-- String utils, feel free to use in your own script.

string.startsWith = function(self, str)
	return self:find('^' .. str) ~= nil
end

string.endsWith = function(str, ending)
	return ending == '' or str:sub(-(#ending)) == ending
end

string.toUpper = function(str)
	res, c = str:gsub('^%l', string.upper)
	return res
end

string.removeEnd = function(str, rem)
	return (str:gsub('^(.-)' .. rem .. '$', '%1'))
end

string.removeStart = function(str, rem)
	return (str:gsub('^' .. rem .. '(.-)$', '%1'))
end

local isx64 = gg.getTargetInfo().x64
local metadata = gg.getRangesList('global-metadata.dat')
local TYPE_PTR = isx64 and gg.TYPE_QWORD or gg.TYPE_DWORD

if #metadata > 0 then
	metadata = metadata[1]
end

function explorer.setAllRanges()
	gg.setRanges(gg.REGION_JAVA_HEAP | gg.REGION_C_HEAP | gg.REGION_C_ALLOC | gg.REGION_C_DATA | gg.REGION_C_BSS | gg.REGION_PPSSPP |
					             gg.REGION_ANONYMOUS | gg.REGION_JAVA | gg.REGION_STACK | gg.REGION_ASHMEM | gg.REGION_VIDEO | gg.REGION_OTHER |
					             gg.REGION_BAD | gg.REGION_CODE_APP | gg.REGION_CODE_SYS)
end

-- Check wether the metadata class name pointer is suitable to find instances. Returns boolean.
-- Use it if you know what you are doing

function explorer.isClassPointer(address)
	local t = {}
	t[1] = {}
	t[1].address = address - (isx64 and 0x10 or 0x8)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_WRITABLE)
	if t[1] == nil then
		return false
	end

	t[1].address = address - (isx64 and 0x8 or 0x4)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_NO)
	if t[1] == nil then
		return false
	end

	t[1].address = address + (isx64 and 0x8 or 0x4)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_READ_ONLY)
	if t[1] == nil then
		return false
	end
	return true
end

function explorer.getClassMetadataPtr(classname)
	if type(classname) ~= 'string' then
		explorer.print('🔴 explorer.getClassMetadataPtr: expected string for parameter classname, got ' .. type(classname))
		return {}
	end

	explorer.setAllRanges()
	gg.clearResults()
	local stringBytes = gg.bytes(classname, 'UTF-8')
	local searchStr = '0'
	for k, v in ipairs(stringBytes) do
		searchStr = searchStr .. '; ' .. v
	end
	searchStr = searchStr .. '; 0::' .. (2 + #stringBytes)

	gg.searchNumber(searchStr, gg.TYPE_BYTE, false, gg.SIGN_EQUAL, metadata.start, metadata['end'], 2)

	if gg.getResultsCount() < 2 then
		if explorer.debug then -- Changed from 'debug' to 'explorer.debug'
			print('🔴 explorer.getClassMetadataPtr: can\'t find ' .. classname .. ' in metadata')
		end
		return 0
	end
	return gg.getResults(2)[2].address
end

function explorer.getAllocatedClassPtr(metadataPtr)
	local addr = 0x0
	for k, v in pairs(gg.getRangesList('libc_malloc')) do -- Consider other memory regions if needed
		gg.clearResults()
		gg.searchNumber(string.format('%X', metadataPtr) .. 'h', TYPE_PTR, false, gg.SIGN_EQUAL, v.start, v['end'], 0)

		local results = gg.getResults(100000)
		gg.clearResults()

		for i, res in ipairs(results) do
			if explorer.isClassPointer(res.address) then
				addr = res.address - (isx64 and 0x10 or 0x8)
				break
			end
		end
		if addr > 0 then
			break
		end
	end
	if (explorer.debug and (addr == 0)) then -- Changed from 'debug' to 'explorer.debug'
		explorer.print('🔴 explorer.getAllocatedClassPtr: there is no valid pointer for ' .. string.format('%X', metadataPtr))
	end
	return addr
end

-- Get instances of class. Returns table with search results or empty table.
-- Added namespace parameter as it's often needed.
function explorer.getInstances(className, namespace) -- Added namespace
	-- Namespace handling can be tricky with just string search in metadata.
	-- For simplicity, this version primarily relies on className.
	-- A more robust solution would involve parsing metadata more deeply if namespaces are ambiguous.
	if namespace and explorer.debug then
		explorer.print("ℹ️ explorer.getInstances: namespace parameter '"..tostring(namespace).."' is provided but current basic implementation might not fully utilize it for disambiguation if class names are identical across namespaces. Advanced parsing would be needed.")
	end

	local mPtr = explorer.getClassMetadataPtr(className)
	if ((mPtr == 0) or (mPtr == nil)) then
		return {}
	end
	local allocPtr = explorer.getAllocatedClassPtr(mPtr)
	if (allocPtr == 0) then
		return {}
	end
	gg.setRanges(gg.REGION_ANONYMOUS) -- Might need to be broader depending on the game
	gg.clearResults()
	local r = {}
	r[1] = {}
	r[1].address = allocPtr
	r[1].flags = TYPE_PTR
	gg.loadResults(r)
	gg.searchPointer(0)
	r = gg.getResults(100000) -- Consider adjusting max results if necessary
	if ((#r == 0) and explorer.debug) then -- Changed from 'debug' to 'explorer.debug'
		explorer.print('🔴 explorer.getInstances: there are no instances for the ' .. className .. ', try to load the class first')
	end
	gg.clearResults()
	return r
end


-- Patch libil2cpp.so;
-- patchedBytes is a table which contains patches that can be either a dword number or a string containing opcode
-- or a string containig hex (must start with "h" and contain only 4 bytes each).
-- Consider using explorer.editFunction
-- You shouldn't use it in your scripts

function explorer.patchLib(offset, offsetX32, patchedBytes, patchedBytesX32)
	gg.clearResults()
	if libStart == 0 then
		explorer.getLib()
	end
	local patch = {}
	if not isx64 then
		patchedBytes = patchedBytesX32
		offset = offsetX32
	end
	if (patchedBytes == nil or offset == nil) then
		explorer.print('🔴 explorer.patchLib: there is no valid patch for current architecture')
		return
	end
	local currAddress = libStart + offset
	for k, v in ipairs(patchedBytes) do
		local t = {}
		t[1] = {}
		t[1].address = currAddress
		t[1].flags = gg.TYPE_DWORD
		if type(v) == 'number' then
			t[1].value = v
			gg.setValues(t)
		end
		if type(v) == 'string' then
			if v:startsWith('h') then
				t[1].value = v
				gg.setValues(t)
			else
				t[1].value = (isx64 and '~A8 ' or '~A ') .. v
				gg.setValues(t)
			end
		end
		currAddress = currAddress + 4
	end
end

function explorer.getLibStart()
	return libStart
end

-- Call explorer.getLib in case you need access to libStart

function explorer.getLib()
	explorer.setAllRanges()
	local libil2cpp
	if gg.getRangesList('libil2cpp.so')[1] ~= nil then
		libStart = gg.getRangesList('libil2cpp.so')[1].start
		return
	end

	-- Fallback search method (can be unreliable)
	explorer.print("⚠️ explorer.getLib: 'libil2cpp.so' not found directly in ranges. Attempting fallback search...")
	local ranges = gg.getRangesList() -- Search all executable ranges if specific ones fail
	for i, range in pairs(ranges) do
		if range.isExecutable then -- Only search executable memory
			gg.clearResults()
			-- A common string in libil2cpp.so, adjust if needed for your target
			gg.searchNumber("il2cpp_init", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, range['start'], range['end'], 1)
			if gg.getResultsCount() > 0 then
					libStart = range.start -- Approximate start, may not be exact base
					explorer.print("⚠️ explorer.getLib: Found potential libil2cpp range via string search. Start: " .. string.format('%X', libStart))
					return
			end
		end
	end

	if libStart == 0x0 then
		explorer.print('🔴 explorer.getLib: failed to get libil2cpp.so address, try entering the game first')
	end
end

-- Get field value in instance.
-- instance: table { address = 0xADDRESS } or just the address number
-- offset: number (will use offsetX32 if not x64 and offsetX32 is provided)
-- fieldName: string (optional, for debugging)
-- valueType: gg.TYPE_
function explorer.getField(instance, offset, fieldName, valueType, offsetX32)
	local instanceAddress
	if type(instance) == 'table' and type(instance.address) == 'number' then
		instanceAddress = instance.address
	elseif type(instance) == 'number' then
		instanceAddress = instance
	else
		explorer.print('🔴 explorer.getField: expected table with address or number for parameter instance, got ' .. type(instance))
		return nil
	end

	if type(valueType) ~= 'number' then
		explorer.print('🔴 explorer.getField: expected number for valueType, got ' .. type(valueType))
		return nil
	end

	local currentOffset
	if not isx64 and offsetX32 ~= nil then
		currentOffset = offsetX32
	elseif offset ~= nil then
		currentOffset = offset
	else
		explorer.print('🔴 explorer.getField: offset for this architecture is not specified')
		return nil
	end
	
	if type(currentOffset) ~= 'number' then
	    explorer.print('🔴 explorer.getField: offset must be a number, got '.. type(currentOffset))
	    return nil
	end

	return explorer.readValue(instanceAddress + currentOffset, valueType)
end


-- Edit field value in instance.
function explorer.editField(instance, offset, fieldName, valueType, value, offsetX32)
	local instanceAddress
	if type(instance) == 'table' and type(instance.address) == 'number' then
		instanceAddress = instance.address
	elseif type(instance) == 'number' then
		instanceAddress = instance
	else
		explorer.print('🔴 explorer.editField: expected table with address or number for parameter instance, got ' .. type(instance))
		return
	end

	if type(valueType) ~= 'number' then
		explorer.print('🔴 explorer.editField: expected number for parameter valueType, got ' .. type(valueType))
		return
	end
	-- Value can be number or string (for hex)
	if not (type(value) == 'number' or type(value) == 'string') then
		explorer.print('🔴 explorer.editField: expected number or string for parameter value, got ' .. type(value))
		return
	end

	local currentOffset
	if not isx64 and offsetX32 ~= nil then
		currentOffset = offsetX32
	elseif offset ~= nil then
		currentOffset = offset
	else
		explorer.print('🔴 explorer.editField: offset for this architecture is not specified')
		return
	end
	
	if type(currentOffset) ~= 'number' then
	    explorer.print('🔴 explorer.editField: offset must be a number, got '.. type(currentOffset))
	    return
	end

	local t = {}
	t[1] = {}
	t[1].address = instanceAddress + currentOffset
	t[1].flags = valueType
	t[1].value = value
	gg.setValues(t)
end

-- Get static field value.
-- className: string
-- fieldName: string (used for clarity, actual lookup might be more complex or direct via offset if known)
-- namespace: string (optional)
-- valueType: gg.TYPE_
-- staticFieldDataOffset: offset from class object to static field data area (game specific)
-- fieldOffsetInStaticData: offset of the specific field within the static data area (game specific)
function explorer.getStaticField(className, fieldName, namespace, valueType, staticFieldDataOffset, fieldOffsetInStaticData)
    if type(className) ~= 'string' then
        explorer.print('🔴 explorer.getStaticField: expected string for parameter className, got ' .. type(className))
        return nil
    end
    if type(fieldName) ~= 'string' then -- Though might not be directly used if offsets are known
        explorer.print('🔴 explorer.getStaticField: expected string for parameter fieldName, got ' .. type(fieldName))
        return nil
    end
    if namespace and type(namespace) ~= 'string' then
        explorer.print('🔴 explorer.getStaticField: expected string or nil for parameter namespace, got ' .. type(namespace))
        return nil
    end
    if type(valueType) ~= 'number' then
        explorer.print('🔴 explorer.getStaticField: expected number for valueType, got ' .. type(valueType))
        return nil
    end
    -- For a robust getStaticField, we usually need the address of the Class object itself (Il2CppClass*)
    -- and then an offset to its static_fields pointer, then the offset of the specific field.
    -- The current Il2CppExplorer by HTCheater doesn't have a direct way to get Il2CppClass* easily
    -- without deeper metadata parsing or assumptions.
    -- The `explorer.getClassMetadataPtr` gets a pointer *within* metadata, not the runtime Il2CppClass object.
    -- The `explorer.getAllocatedClassPtr` gets a pointer to the *allocated class structure* if it's a MonoBehaviour or similar.

    -- This is a placeholder implementation. A real one needs more advanced metadata parsing or specific game offsets.
    -- The provided `Il2cppApi.lua` (from BadCase's toolbox) has more in-depth parsing.
    -- For HTCheater's explorer, you'd typically find the class, then its static field data pointer, then the field.

    -- Attempt to find the class object pointer (this is a common pattern but might not always work or be the static fields pointer directly)
    local mPtr = explorer.getClassMetadataPtr(className) -- This is metadata name pointer
    if mPtr == 0 or mPtr == nil then
        explorer.print("🔴 explorer.getStaticField: Could not find metadata pointer for class: " .. className)
        return nil
    end

    local classObjectPtr = explorer.getAllocatedClassPtr(mPtr) -- This gets the allocated class object
    if classObjectPtr == 0 or classObjectPtr == nil then
        explorer.print("🔴 explorer.getStaticField: Could not find allocated class object for: " .. className .. ". Static fields might not be directly accessible this way or class not initialized.")
        -- Sometimes static fields are accessed differently, e.g., directly from a pointer in the class's metadata image
        -- or via a dedicated static fields table.
        -- This is a simplified approach.
        return nil
    end

    -- The following offsets are highly game-specific and need to be found via reversing or a better dumper.
    -- This is where you'd use `staticFieldDataOffset` and `fieldOffsetInStaticData` if you knew them.
    -- Example: addressOfStaticFields = explorer.readPointer(classObjectPtr + offsetToStaticFieldsPointer)
    --          value = explorer.readValue(addressOfStaticFields + offsetOfActualField, valueType)

    -- For now, returning nil as a generic solution is hard without specific offsets or deeper parsing.
    -- The main script calling this will need to provide the correct offsets if this simplified approach fails.
    if staticFieldDataOffset and fieldOffsetInStaticData then
        local staticDataBlockAddress = explorer.readPointer(classObjectPtr + staticFieldDataOffset)
        if staticDataBlockAddress and staticDataBlockAddress ~= 0 then
            return explorer.readValue(staticDataBlockAddress + fieldOffsetInStaticData, valueType)
        else
            explorer.print("🔴 explorer.getStaticField: Could not read static data block address for " .. className)
            return nil
        end
    else
         explorer.print("🔴 explorer.getStaticField: staticFieldDataOffset and fieldOffsetInStaticData are required for " .. className .. ". This function is a placeholder without them.")
         -- A common pattern for singletons is that the "Instance" field itself is static.
         -- If fieldName is "Instance", we might try reading it directly if the classObjectPtr points to where static fields are.
         -- This is a BIG assumption.
         if fieldName == "Instance" then
             -- Assuming classObjectPtr + fieldOffsetInStaticData (if known) would be the "Instance" field.
             -- This needs the offset of the "Instance" field within the static fields block.
             if fieldOffsetInStaticData then
                local instancePtr = explorer.readPointer(classObjectPtr + fieldOffsetInStaticData)
                if instancePtr and instancePtr ~= 0 then
                    -- This pointer should be the address of the singleton instance.
                    -- We need to return an "instance-like" table for the main script.
                    return { address = instancePtr, __className = className }
                else
                    explorer.print("🔴 explorer.getStaticField: Tried to read 'Instance' for " .. className .. " but pointer was null or invalid.")
                    return nil
                end
             else
                explorer.print("🔴 explorer.getStaticField: Missing fieldOffsetInStaticData for 'Instance' field of " .. className)
                return nil
             end
         end
        return nil
    end
end


function explorer.getFunction(className, functionName)
	if type(functionName) ~= 'string' then
		explorer.print('🔴 explorer.getFunction: expected string for parameter functionName, got ' .. type(functionName))
		return nil
	end
	if ((type(className) ~= 'nil') and (type(className) ~= 'string')) then
		explorer.print('🔴 explorer.getFunction: expected string for parameter className, got ' .. type(className))
		return nil
	end
	explorer.setAllRanges()
	gg.clearResults()
	local stringBytes = gg.bytes(functionName, 'UTF-8')
	local searchStr = '0'
	for k, v in ipairs(stringBytes) do
		searchStr = searchStr .. '; ' .. v
	end
	searchStr = searchStr .. '; 0::' .. (2 + #stringBytes)

	gg.searchNumber(searchStr, gg.TYPE_BYTE, false, gg.SIGN_EQUAL, metadata.start, metadata['end'], (className == nil) and 2 or nil)
	gg.refineNumber('0; ' .. stringBytes[1], gg.TYPE_BYTE)
	gg.refineNumber(stringBytes[1], gg.TYPE_BYTE)

	if gg.getResultsCount() == 0 then
		explorer.print('Can\'t find ' .. functionName .. ' in metadata')
		local r = {}
		return r
	end

	local addr = 0x0

	for index, result in pairs(gg.getResults(100000)) do
		for k, v in pairs(gg.getRangesList('libc_malloc')) do -- Consider other memory regions
			gg.clearResults()
			gg.searchNumber(string.format('%X', result.address) .. 'h', TYPE_PTR, false, gg.SIGN_EQUAL, v.start, v['end'], 0)

			local results = gg.getResults(100)
			gg.clearResults()

			for i, res in ipairs(results) do
				if explorer.isFunctionPointer(res.address, className) then
					addr = explorer.readPointer(res.address - (isx64 and 0x10 or 0x8))
					break
				end
			end
			if addr > 0 then
				break
			end
		end
		if addr > 0 then break end -- Break outer loop if found
	end

	if addr == 0 then
		explorer.print('🔴 explorer.getFunction: there is no valid pointer for ' .. functionName ..
						               ((className == nil) and '' or (' in ' .. className)))
		return nil
	end

	if libStart == 0 then
		explorer.getLib()
		if libStart == 0 then -- Still 0 after trying to get it
		    explorer.print('🔴 explorer.getFunction: libil2cpp.so start address is 0. Cannot calculate offset.')
		    return addr -- Return absolute address if libStart is unknown
		end
	end

	addr = addr - libStart

	explorer.print('🟢 explorer.getFunction: offset for ' .. functionName .. ': ' .. string.format('%X', addr))

	return addr
end

-- Find function offset and edit assembly
-- className should be specified to prevent finding wrong functions with the same name
function explorer.editFunction(className, functionName, patchedBytes, patchedBytesX32)
	if ((type(className) ~= 'nil') and (type(className) ~= 'string')) then
		explorer.print('🔴 explorer.editFunction: expected string or nil for parameter className, got ' .. type(className))
		return
	end
	if type(functionName) ~= 'string' then
		explorer.print('🔴 explorer.editFunction: expected string for parameter functionName, got ' .. type(functionName))
		return
	end
	local offs = explorer.getFunction(className, functionName)
	if (offs == nil) then
		return
	end
	explorer.patchLib(offs, offs, patchedBytes, patchedBytesX32)
end

function explorer.isFunctionPointer(address, className)
	local t = {}
	t[1] = {}
	t[1].address = address - (isx64 and 0x10 or 0x8)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_EXECUTABLE)
	if t[1] == nil then
		return false
	end

	t[1].address = address - (isx64 and 0x8 or 0x4)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_EXECUTABLE)
	if t[1] == nil then
		return false
	end

	t[1].address = address + (isx64 and 0x8 or 0x4)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_WRITABLE)
	if t[1] == nil then
		return false
	end
	if className ~= nil then
		local classPtrAddr = explorer.readPointer(address + (isx64 and 0x8 or 0x4))
		if not classPtrAddr or classPtrAddr == 0 then return false end

		local classNamePtrAddr = explorer.readPointer(classPtrAddr + (isx64 and 0x10 or 0x8)) -- Offset to name pointer in Il2CppClass
		if not classNamePtrAddr or classNamePtrAddr == 0 then return false end
		
		-- Read the class name from memory
		local max_len = 256 -- Max length for class name to prevent infinite loops
		local found_name_bytes = {}
		for i = 0, max_len - 1 do
			local byte = explorer.readByte(classNamePtrAddr + i)
			if byte == 0 or byte == nil then break end
			table.insert(found_name_bytes, string.char(byte))
		end
		local found_name = table.concat(found_name_bytes)

		if found_name ~= className then
			return false
		end
	end
	return true
end

function explorer.readValue(addr, valueType)
	if type(addr) ~= 'number' or addr == 0 then -- Added check for addr == 0
		explorer.print('🔴 explorer.readValue: expected valid number for parameter addr, got ' .. tostring(addr))
		return nil -- Return nil for invalid address
	end

	if type(valueType) ~= 'number' then
		explorer.print('🔴 explorer.readValue: expected number for parameter valueType, got ' .. type(valueType))
		return nil
	end
	local t = {}
	t[1] = {}
	t[1].address = addr
	t[1].flags = valueType

	t = gg.getValues(t)
    if t and t[1] then
	    return t[1].value
    end
    explorer.print('🔴 explorer.readValue: gg.getValues failed for address ' .. string.format('%X', addr))
    return nil
end

function explorer.readByte(addr)
	return explorer.readValue(addr, gg.TYPE_BYTE)
end

function explorer.readShort(addr) -- WORD is 2 bytes
	return explorer.readValue(addr, gg.TYPE_WORD)
end

function explorer.readInt(addr) -- DWORD is 4 bytes
	return explorer.readValue(addr, gg.TYPE_DWORD)
end

-- returns pointed address
function explorer.readPointer(addr)
	return explorer.readValue(addr, TYPE_PTR)
end

-- Print debug messages
function explorer.print(str)
	if explorer.debug then
		print(str)
	end
end

function explorer.readString(addr)
	-- Unity uses UTF-16LE for System.String
	if type(addr) ~= 'number' or addr == 0 then
		explorer.print('🔴 explorer.readString: wrong argument, expected valid address number, got ' .. tostring(addr))
		return ''
	end
	-- First, read the pointer to the string object itself if addr is a pointer to a pointer (common for fields)
	-- If addr is already the string object, this step might be skipped or adjusted.
	-- Assuming addr is the direct pointer to the string object (like what Il2CppString* would be)

	local len_offset = isx64 and 0x10 or 0x8 -- Offset to m_stringLength in System.String
	local first_char_offset = isx64 and 0x14 or 0xC -- Offset to m_firstChar in System.String

	local len = explorer.readInt(addr + len_offset)

	if len == nil or len <= 0 or len > explorer.maxStringLength then
	    if len and len > explorer.maxStringLength then
	        explorer.print("🟡 explorer.readString: String length " .. len .. " exceeds maxStringLength " .. explorer.maxStringLength)
	    elseif len == nil then
	         explorer.print("🔴 explorer.readString: Failed to read string length at address " .. string.format('%X', addr + len_offset))
	    end
		return '' -- Return empty for invalid length or if reading failed
	end

	local strTable = {}
	for i = 0, len - 1 do -- Loop from 0 to len-1 for characters
		strTable[i+1] = {}
		strTable[i+1].address = addr + first_char_offset + (i * 2) -- Each char is 2 bytes (UTF-16)
		strTable[i+1].flags = gg.TYPE_WORD -- Read as WORD (2 bytes)
	end

	if #strTable == 0 then return "" end -- No characters to read

	strTable = gg.getValues(strTable)
	if not strTable then
	    explorer.print("🔴 explorer.readString: gg.getValues failed for reading string characters.")
	    return ""
	end

	local chars = {}
	for k, v_entry in ipairs(strTable) do
	    if v_entry and v_entry.value then
		    local char_code = v_entry.value
		    -- Basic UTF-16LE to UTF-8, Lua's string.char handles ASCII well.
		    -- For non-ASCII, this might need a proper UTF-16LE to UTF-8 conversion library for full support.
		    -- This basic conversion will work for many common characters.
		    if char_code < 256 then -- Simple case for single-byte UTF-8 representation
		        table.insert(chars, string.char(char_code))
		    else
		        -- This is a simplified placeholder. Proper UTF-16 to UTF-8 is more complex.
		        -- For GameGuardian display, often just trying to get readable chars is enough.
		        -- You might see '?' or other replacement chars for complex Unicode.
		        table.insert(chars, string.char(bit32.extract(char_code, 0, 8))) -- Attempt to get lower byte
		        if bit32.extract(char_code, 8, 8) ~= 0 then -- If there's an upper byte
		             -- table.insert(chars, string.char(bit32.extract(char_code, 8, 8))) -- This might mess up encoding
		        end
		        -- explorer.print("🟡 explorer.readString: Encountered wide character: " .. char_code)
		    end
		else
		    explorer.print("🔴 explorer.readString: Nil entry in strTable from getValues.")
		end
	end
	return table.concat(chars)
end


function explorer.setAlphabet(str)
	if type(str) ~= 'string' then
		explorer.print('🔴 explorer.setAlphabet: wrong argument in explorer.setAlphabet: expected string, got ' .. type(str))
		return
	end
	alphabet = {}
	str:gsub('[%z\1-\127\194-\244][\128-\191]*', function(c)
		local bytes = gg.bytes(c, 'UTF-16LE')
		local utf8Chars = ''
		for k, v in pairs(bytes) do
			utf8Chars = utf8Chars .. string.char(v)
		end
		local short = string.unpack('<i2', utf8Chars) -- Unpack as little-endian short (2 bytes)
		alphabet[short] = c
	end)
end

-- Memory allocation utility (simple version)
-- This is a very basic allocator, not meant for general purpose complex memory management.
memory = {}
local currentAllocAddress = nil
local freeAllocSpace = nil
local allocatedPages = {}
local currentPageIndex = 0

function memory.getcurrentAddress() -- Renamed to avoid conflict
	return currentAllocAddress
end

function memory.getFreeSpace()
	return freeAllocSpace
end

function memory.getPages()
	return allocatedPages
end

function memory.alloc(size_needed)
    size_needed = size_needed or 4096 -- Default to one page if no specific size
    -- Check if current page has enough space
    if currentPageIndex > 0 and freeAllocSpace >= size_needed then
        local alloc_ptr = currentAllocAddress
        currentAllocAddress = currentAllocAddress + size_needed
        freeAllocSpace = freeAllocSpace - size_needed
        explorer.print('🟢 memory.alloc: allocated '..size_needed..' bytes from existing page. New currentAddress: ' .. string.format('%X', currentAllocAddress))
        return alloc_ptr
    end

    -- Need to allocate a new page (or more if size_needed > 4096)
    local num_pages_to_alloc = math.ceil(size_needed / 4096)
    local total_allocated_size = num_pages_to_alloc * 4096
    
    local ptr = gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC, total_allocated_size)
    if not ptr or ptr == 0 then
        explorer.print('🔴 memory.alloc: gg.allocatePage failed to allocate '..total_allocated_size..' bytes.')
        return nil
    end

    currentAllocAddress = ptr
    freeAllocSpace = total_allocated_size
    currentPageIndex = currentPageIndex + 1
    allocatedPages[currentPageIndex] = {start = ptr, size = total_allocated_size, used = 0}
    
    explorer.print('🟢 memory.alloc: allocated new page(s) of '..total_allocated_size..' bytes at ' .. string.format('%X', currentAllocAddress))

    local alloc_ptr = currentAllocAddress
    currentAllocAddress = currentAllocAddress + size_needed
    freeAllocSpace = freeAllocSpace - size_needed
    allocatedPages[currentPageIndex].used = size_needed
    explorer.print('🟢 memory.alloc: allocated '..size_needed..' bytes. New currentAddress: ' .. string.format('%X', currentAllocAddress))
    return alloc_ptr
end


function memory.write(data_table)
	if type(data_table) ~= 'table' then
		explorer.print('🔴 memory.write: expected table for first parameter, got ' .. type(data_table))
		return false, nil
	end

	local spaceNeeded = 0
	for k, v_entry in ipairs(data_table) do -- Use ipairs for ordered table
		if type(v_entry) ~= 'table' or v_entry.value == nil then
			explorer.print('🔴 memory.write: invalid entry in data_table at index ' .. k)
			return false, nil
		end
		if (v_entry.flags == nil) then
			-- Basic type guessing, prefer explicit flags
			if math.type(v_entry.value) == 'float' then
				v_entry.flags = gg.TYPE_FLOAT
			elseif type(v_entry.value) == 'string' and v_entry.value:sub(1,1) == 'h' then -- hex string
			    v_entry.flags = gg.TYPE_DWORD -- Assuming hex strings are for DWORDs, adjust if needed
			else
				v_entry.flags = gg.TYPE_DWORD -- Default
			end
			data_table[k] = v_entry
		end
		spaceNeeded = spaceNeeded + (v_entry.flags == gg.TYPE_STRING and (#v_entry.value + 1) or v_entry.flags) -- Rough estimate for strings
	end

	local startAddress = memory.alloc(spaceNeeded)
	if not startAddress then
		explorer.print('🔴 memory.write: failed to allocate memory for data_table.')
		return false, nil
	end

	local tempWriteTable = {}
	local currentWriteAddr = startAddress
	for k, v_entry in ipairs(data_table) do
		table.insert(tempWriteTable, {
		    address = currentWriteAddr,
		    flags = v_entry.flags,
		    value = v_entry.value
		})
		currentWriteAddr = currentWriteAddr + (v_entry.flags == gg.TYPE_STRING and (#v_entry.value + 1) or v_entry.flags)
	end
	
	local success = gg.setValues(tempWriteTable)
	if not success then
		explorer.print('🔴 memory.write: gg.setValues failed.')
		-- Potentially try to free/mark the allocated space as unused if critical
		return false, nil
	end
	
	explorer.print('🟢 memory.write: successfully wrote ' .. #data_table .. ' items at ' .. string.format('%X', startAddress) .. '. Free space in current page: ' .. freeAllocSpace)
	return true, startAddress -- Return success and start address
end

-- it doesn't actually *free* memory in OS terms but allows reuse of pages for this script's session
function memory.resetAllocator()
	currentAllocAddress = nil
	freeAllocSpace = 0
	currentPageIndex = 0
	-- allocatedPages remains to potentially reuse them if memory.alloc is called again
	-- To truly free, one would need to iterate allocatedPages and call gg.freePage if GG supports it and if it's safe.
	explorer.print('🟢 memory.resetAllocator: Allocator reset. Previously allocated pages can be reused.')
end

-- Initialize alphabet with common characters if not set by user
if next(alphabet) == nil then
    explorer.setAlphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ .,;:!?\"\'@#$%^&*()-+=<>[]{}|/\\`~абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞß")
end

-- Initialize memory allocator
memory.resetAllocator() -- Start with a fresh state

return explorer -- Ensure the explorer table is returned if loaded via require

