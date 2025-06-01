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

local libStart = 0x0
explorer.maxStringLength = 1000
local alphabet = {}

if explorer.printAdvert then
	print('✨ Made with Il2CppExplorer by HTCheater (truonggiangsualai version)')
end

if (explorer.exitOnNotUnityGame and #gg.getRangesList('global-metadata.dat') < 1) then
	print('🔴 Vui lòng chọn game Unity.')
	os.exit()
end

-- String utils
string.startsWith = function(self, str)
	return self:find('^' .. str) ~= nil
end

string.endsWith = function(str, ending)
	return ending == '' or str:sub(-(#ending)) == ending
end

string.toUpper = function(str)
	local res, c = str:gsub('^%l', string.upper)
	return res
end

string.removeEnd = function(str, rem)
	return (str:gsub('^(.-)' .. rem .. '$', '%1'))
end

string.removeStart = function(str, rem)
	return (str:gsub('^' .. rem .. '(.-)$', '%1'))
end

local isx64 = gg.getTargetInfo().x64
local metadata_ranges = gg.getRangesList('global-metadata.dat')
local TYPE_PTR = isx64 and gg.TYPE_QWORD or gg.TYPE_DWORD
local METADATA_INFO

local function initMetadataIfNeeded()
    if METADATA_INFO then return end
    if #metadata_ranges > 0 then
        METADATA_INFO = metadata_ranges[1]
        if explorer.debug then
            explorer.print("ℹ️ Metadata Range: start=0x" .. string.format("%X", METADATA_INFO.start) .. ", end=0x" .. string.format("%X", METADATA_INFO['end']))
        end
    else
        explorer.print("🔴 Không tìm thấy 'global-metadata.dat'. Các hàm phụ thuộc metadata sẽ không hoạt động.")
        METADATA_INFO = {start = 0, ['end'] = 0} 
    end
end


function explorer.setAllRanges()
	gg.setRanges(gg.REGION_JAVA_HEAP | gg.REGION_C_HEAP | gg.REGION_C_ALLOC | gg.REGION_C_DATA | gg.REGION_C_BSS | gg.REGION_PPSSPP |
					             gg.REGION_ANONYMOUS | gg.REGION_JAVA | gg.REGION_STACK | gg.REGION_ASHMEM | gg.REGION_VIDEO | gg.REGION_OTHER |
					             gg.REGION_BAD | gg.REGION_CODE_APP | gg.REGION_CODE_SYS)
end

function explorer.isClassPointer(address)
	local t = {}
	t[1] = {}
	t[1].address = address - (isx64 and 0x10 or 0x8)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_WRITABLE)
	if t[1] == nil then return false end

	t[1].address = address - (isx64 and 0x8 or 0x4)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_NO)
	if t[1] == nil then return false end

	t[1].address = address + (isx64 and 0x8 or 0x4)
	t[1].flags = TYPE_PTR
	gg.clearResults()
	gg.loadResults(t)
	t = gg.getResults(1, nil, nil, nil, nil, nil, nil, nil, gg.POINTER_READ_ONLY)
	if t[1] == nil then return false end
	return true
end

function explorer.getClassMetadataPtr(classname)
	initMetadataIfNeeded()
	if type(classname) ~= 'string' then
		explorer.print('🔴 explorer.getClassMetadataPtr: classname phải là string, nhận được ' .. type(classname))
		return 0 
	end
	if METADATA_INFO.start == 0 then return 0 end 

	explorer.setAllRanges()
	gg.clearResults()
	local stringBytes = gg.bytes(classname, 'UTF-8')
	if #stringBytes == 0 then return 0 end
	local searchStr = '0'
	for k, v in ipairs(stringBytes) do
		searchStr = searchStr .. '; ' .. v
	end
	searchStr = searchStr .. '; 0::' .. (2 + #stringBytes)

	gg.searchNumber(searchStr, gg.TYPE_BYTE, false, gg.SIGN_EQUAL, METADATA_INFO.start, METADATA_INFO['end'], 2)

	if gg.getResultsCount() < 2 then
		if explorer.debug then
			explorer.print('🔴 explorer.getClassMetadataPtr: không tìm thấy ' .. classname .. ' trong metadata')
		end
		return 0
	end
	return gg.getResults(2)[2].address
end

function explorer.getAllocatedClassPtr(metadataPtr)
    if metadataPtr == 0 or metadataPtr == nil then return 0 end
	local addr = 0x0
    local search_ranges = {"REGION_C_HEAP", "REGION_ANONYMOUS", "libc_malloc", "linker_alloc"}
	for _, range_name_part in ipairs(search_ranges) do
	    for k, v in pairs(gg.getRangesList(range_name_part)) do
		    gg.clearResults()
		    gg.searchNumber(string.format('%X', metadataPtr) .. 'h', TYPE_PTR, false, gg.SIGN_EQUAL, v.start, v['end'], 0)
		    local results = gg.getResults(100000) 
		    gg.clearResults()
		    for i, res in ipairs(results) do
			    if explorer.isClassPointer(res.address) then
				    addr = res.address - (isx64 and 0x10 or 0x8)
				    goto found_allocated_ptr 
			    end
		    end
	    end
	end
    ::found_allocated_ptr::
	if (explorer.debug and (addr == 0)) then
		explorer.print('🔴 explorer.getAllocatedClassPtr: không có con trỏ hợp lệ cho metadataPtr 0x' .. string.format('%X', metadataPtr))
	end
	return addr
end

function explorer.getInstances(className, namespace) 
	if namespace and explorer.debug then
		explorer.print("ℹ️ explorer.getInstances: namespace '"..tostring(namespace).."' được cung cấp. Logic tìm kiếm hiện tại chủ yếu dựa vào className.")
	end
	local mPtr = explorer.getClassMetadataPtr(className)
	if mPtr == 0 then return {} end
	local allocPtr = explorer.getAllocatedClassPtr(mPtr)
	if allocPtr == 0 then return {} end
	
	gg.setRanges(gg.REGION_ANONYMOUS) 
	gg.clearResults()
	local r = {{address = allocPtr, flags = TYPE_PTR}}
	gg.loadResults(r)
	gg.searchPointer(0) 
	r = gg.getResults(10000) 
	if (#r == 0 and explorer.debug) then
		explorer.print('🔴 explorer.getInstances: không có instance cho ' .. className)
	end
	gg.clearResults()
	return r
end

function explorer.getLib()
    if libStart ~= 0x0 then return end 
	explorer.setAllRanges()
	local libRanges = gg.getRangesList('libil2cpp.so')
	if #libRanges > 0 then
	    for _, rangeEntry in ipairs(libRanges) do
	        if rangeEntry.isExecutable then 
	            libStart = rangeEntry.start
	            explorer.print("🟢 explorer.getLib: libil2cpp.so found at 0x"..string.format("%X", libStart))
	            return
	        end
	    end
	end
	explorer.print("⚠️ explorer.getLib: 'libil2cpp.so' not found directly. Attempting fallback.")
	local allRanges = gg.getRangesList()
	for _, rangeEntry in ipairs(allRanges) do
		if rangeEntry.isExecutable and rangeEntry.name and string.find(rangeEntry.name, "libil2cpp.so") then
			libStart = rangeEntry.start
			explorer.print("🟢 explorer.getLib: libil2cpp.so (fallback) found at 0x"..string.format("%X", libStart))
			return
		end
	end
	if libStart == 0x0 then
		explorer.print('🔴 explorer.getLib: không thể lấy địa chỉ libil2cpp.so.')
	end
end

function explorer.getField(instance, offset, fieldName, valueType, offsetX32)
	local instanceAddress
	if type(instance) == 'table' and type(instance.address) == 'number' then
		instanceAddress = instance.address
	elseif type(instance) == 'number' then
		instanceAddress = instance
	else
		explorer.print('🔴 explorer.getField: instance phải là table có address hoặc number, nhận được ' .. type(instance))
		return nil
	end
	if type(valueType) ~= 'number' then
		explorer.print('🔴 explorer.getField: valueType phải là number, nhận được ' .. type(valueType))
		return nil
	end
	local currentOffset = isx64 and offset or (offsetX32 or offset)
	if currentOffset == nil then
		explorer.print('🔴 explorer.getField: offset không được chỉ định cho kiến trúc này.')
		return nil
	end
	if type(currentOffset) ~= 'number' then
	    explorer.print('🔴 explorer.getField: offset phải là number, nhận được '.. type(currentOffset))
	    return nil
	end
	return explorer.readValue(instanceAddress + currentOffset, valueType)
end

function explorer.getStaticField(className, fieldName, namespace, valueType, staticFieldDataPointerOffset, fieldOffsetInStaticData)
    local was_debug = explorer.debug
    -- explorer.debug = true -- Bật debug tạm thời cho hàm này nếu cần
    
    if type(className) ~= 'string' then explorer.print('🔴 getStaticField: className phải là string.'); if not was_debug then explorer.debug = false end; return nil end
    if type(fieldName) ~= 'string' then explorer.print('🔴 getStaticField: fieldName phải là string.'); if not was_debug then explorer.debug = false end; return nil end
    if namespace and type(namespace) ~= 'string' then explorer.print('🔴 getStaticField: namespace phải là string hoặc nil.'); if not was_debug then explorer.debug = false end; return nil end
    if type(valueType) ~= 'number' then explorer.print('🔴 getStaticField: valueType phải là number.'); if not was_debug then explorer.debug = false end; return nil end

    local mPtr = explorer.getClassMetadataPtr(className)
    if mPtr == 0 then explorer.print("🔴 getStaticField: Không tìm thấy metadata ptr cho class: " .. className); if not was_debug then explorer.debug = false end; return nil end
    
    local classObjectRuntimePtr = explorer.getAllocatedClassPtr(mPtr) 
    if classObjectRuntimePtr == 0 then 
        explorer.print("🔴 getStaticField: Không tìm thấy allocated class object cho: " .. className); 
        if not was_debug then explorer.debug = false end; 
        return nil 
    end

    if not staticFieldDataPointerOffset or not fieldOffsetInStaticData then
        explorer.print("🔴 getStaticField: Cần `staticFieldDataPointerOffset` (0x" .. string.format("%X", staticFieldDataPointerOffset or -1) .. ") và `fieldOffsetInStaticData` (0x" .. string.format("%X", fieldOffsetInStaticData or -1) .. ") cho " .. className .. "." .. fieldName)
        if not was_debug then explorer.debug = false end
        return nil
    end

    local staticFieldsBlockPtr = explorer.readPointer(classObjectRuntimePtr + staticFieldDataPointerOffset)
    if not staticFieldsBlockPtr or staticFieldsBlockPtr == 0 then
        explorer.print("🔴 getStaticField: Không đọc được con trỏ khối static data cho " .. className .. " tại classObjectPtr (0x" .. string.format("%X", classObjectRuntimePtr) ..") + 0x" .. string.format("%X", staticFieldDataPointerOffset))
        if not was_debug then explorer.debug = false end
        return nil
    end
    
    explorer.print("ℹ️ getStaticField: staticFieldsBlockPtr cho " .. className .. " = 0x" .. string.format("%X", staticFieldsBlockPtr))
    local fieldValue = explorer.readValue(staticFieldsBlockPtr + fieldOffsetInStaticData, valueType)
    explorer.print("ℹ️ getStaticField: ".. className .. "." .. fieldName .. " (static) value at 0x".. string.format("%X", staticFieldsBlockPtr + fieldOffsetInStaticData) .." = " .. tostring(fieldValue))

    if fieldValue ~= nil and valueType == TYPE_PTR and fieldValue ~= 0 then
        if fieldName == "Instance" or fieldName == "instance" then
            if not was_debug then explorer.debug = false end
            return { address = fieldValue, __className = className }
        end
    end
    
    if not was_debug then explorer.debug = false end
    return fieldValue
end

function explorer.readValue(addr, valueType)
	if type(addr) ~= 'number' or addr == 0 then
		explorer.print('🔴 explorer.readValue: địa chỉ không hợp lệ ' .. tostring(addr))
		return nil
	end
	if type(valueType) ~= 'number' then
		explorer.print('🔴 explorer.readValue: valueType không hợp lệ ' .. type(valueType))
		return nil
	end
	local t = {{address = addr, flags = valueType}}
	t = gg.getValues(t)
    if t and t[1] then return t[1].value end
    explorer.print('🔴 explorer.readValue: gg.getValues thất bại cho địa chỉ 0x' .. string.format('%X', addr))
    return nil
end

function explorer.readByte(addr) return explorer.readValue(addr, gg.TYPE_BYTE) end
function explorer.readShort(addr) return explorer.readValue(addr, gg.TYPE_WORD) end
function explorer.readInt(addr) return explorer.readValue(addr, gg.TYPE_DWORD) end
function explorer.readPointer(addr) return explorer.readValue(addr, TYPE_PTR) end

function explorer.print(str)
	if explorer.debug then print(str) end
end

function explorer.readString(addr)
	if type(addr) ~= 'number' or addr == 0 then
		explorer.print('🔴 explorer.readString: địa chỉ không hợp lệ: ' .. tostring(addr))
		return ''
	end
	local len_offset = isx64 and 0x10 or 0x8 
	local first_char_offset = isx64 and 0x14 or 0xC
	local len = explorer.readInt(addr + len_offset)

	if len == nil or len <= 0 or len > explorer.maxStringLength then
	    if len and len > explorer.maxStringLength then explorer.print("🟡 readString: Độ dài chuỗi " .. len .. " > max " .. explorer.maxStringLength)
	    elseif len == nil then explorer.print("🔴 readString: Không đọc được độ dài chuỗi tại 0x" .. string.format('%X', addr + len_offset)) end
		return ''
	end

	local strTable = {}
	for i = 0, len - 1 do
		strTable[i+1] = {address = addr + first_char_offset + (i * 2), flags = gg.TYPE_WORD}
	end
	if #strTable == 0 then return "" end
	strTable = gg.getValues(strTable)
	if not strTable then explorer.print("🔴 readString: gg.getValues thất bại khi đọc ký tự."); return "" end

	local chars = {}
	for _, v_entry in ipairs(strTable) do
	    if v_entry and v_entry.value then
		    local char_code = v_entry.value
		    if char_code >= 0 and char_code < 0xD800 then 
		        table.insert(chars, utf8.char(char_code)) 
		    elseif char_code >= 0xE000 and char_code <= 0xFFFF then -- Basic Multilingual Plane, excluding surrogates
		        table.insert(chars, utf8.char(char_code))
            else
		        table.insert(chars, "?") 
		    end
		else
		    explorer.print("🔴 readString: Mục nil trong strTable.")
		end
	end
	return table.concat(chars)
end

-- Memory allocation
memory = {}
local currentAllocAddress = nil
local freeAllocSpace = nil
local allocatedPages = {}
local currentPageIndex = 0

function memory.getcurrentAddress() return currentAllocAddress end
function memory.getFreeSpace() return freeAllocSpace end
function memory.getPages() return allocatedPages end

function memory.alloc(size_needed)
    size_needed = size_needed or 4096 -- Dòng 390, đảm bảo không có ký tự lạ
    if currentPageIndex > 0 and allocatedPages[currentPageIndex] and freeAllocSpace >= size_needed then
        local alloc_ptr = currentAllocAddress
        currentAllocAddress = currentAllocAddress + size_needed
        freeAllocSpace = freeAllocSpace - size_needed
        if allocatedPages[currentPageIndex] then allocatedPages[currentPageIndex].used = allocatedPages[currentPageIndex].used + size_needed end
        explorer.print('🟢 memory.alloc: cấp '..size_needed..' bytes từ trang hiện tại. Địa chỉ mới: 0x' .. string.format('%X', currentAllocAddress))
        return alloc_ptr
    end
    local num_pages_to_alloc = math.ceil(size_needed / 4096)
    local total_allocated_size = num_pages_to_alloc * 4096
    local ptr = gg.allocatePage(gg.PROT_READ | gg.PROT_WRITE | gg.PROT_EXEC, total_allocated_size)
    if not ptr or ptr == 0 then
        explorer.print('🔴 memory.alloc: gg.allocatePage thất bại khi cấp '..total_allocated_size..' bytes.')
        return nil
    end
    currentAllocAddress = ptr
    freeAllocSpace = total_allocated_size
    currentPageIndex = currentPageIndex + 1
    allocatedPages[currentPageIndex] = {start = ptr, size = total_allocated_size, used = 0}
    explorer.print('🟢 memory.alloc: cấp trang mới '..total_allocated_size..' bytes tại 0x' .. string.format('%X', currentAllocAddress))
    local alloc_ptr = currentAllocAddress
    currentAllocAddress = currentAllocAddress + size_needed
    freeAllocSpace = freeAllocSpace - size_needed
    allocatedPages[currentPageIndex].used = size_needed
    explorer.print('🟢 memory.alloc: đã cấp '..size_needed..' bytes. Địa chỉ mới: 0x' .. string.format('%X', currentAllocAddress))
    return alloc_ptr
end

function memory.write(data_table)
	if type(data_table) ~= 'table' then explorer.print('🔴 memory.write: data_table phải là table.'); return false, nil end
	local spaceNeeded = 0
	for k, v_entry in ipairs(data_table) do
		if type(v_entry) ~= 'table' or v_entry.value == nil then explorer.print('🔴 memory.write: entry lỗi tại index ' .. k); return false, nil end
		if (v_entry.flags == nil) then
			if math.type(v_entry.value) == 'float' then v_entry.flags = gg.TYPE_FLOAT
			elseif type(v_entry.value) == 'string' and v_entry.value:sub(1,1) == 'h' then v_entry.flags = gg.TYPE_DWORD 
			else v_entry.flags = gg.TYPE_DWORD end
			data_table[k] = v_entry
		end
		spaceNeeded = spaceNeeded + (v_entry.flags == gg.TYPE_STRING and (utf8.len(v_entry.value) * 2 + 2) or v_entry.flags) 
	end
	local startAddress = memory.alloc(spaceNeeded)
	if not startAddress then explorer.print('🔴 memory.write: không cấp phát được bộ nhớ.'); return false, nil end
	local tempWriteTable = {}
	local currentWriteAddr = startAddress
	for k, v_entry in ipairs(data_table) do
		table.insert(tempWriteTable, {address = currentWriteAddr, flags = v_entry.flags, value = v_entry.value})
		currentWriteAddr = currentWriteAddr + (v_entry.flags == gg.TYPE_STRING and (utf8.len(v_entry.value) * 2 + 2) or v_entry.flags)
	end
	if not gg.setValues(tempWriteTable) then explorer.print('🔴 memory.write: gg.setValues thất bại.'); return false, nil end
	explorer.print('🟢 memory.write: đã ghi ' .. #data_table .. ' items tại 0x' .. string.format('%X', startAddress))
	return true, startAddress
end

function memory.resetAllocator()
	currentAllocAddress = nil
	freeAllocSpace = 0
	currentPageIndex = 0
	explorer.print('🟢 memory.resetAllocator: Bộ cấp phát đã được reset.')
end

-- Initialize alphabet (có thể không cần nếu readString dùng utf8.char)
-- if next(alphabet) == nil then
--     explorer.setAlphabet("...") 
-- end

memory.resetAllocator()
initMetadataIfNeeded() -- Khởi tạo METADATA_INFO

return explorer
