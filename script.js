function dump() {
  console.log("Searching global-metadata.dat in memory...")
  for (const range of Process.enumerateRanges({ protection: "r--", coalesce: true })) {
    Memory.scan(range.base, range.size, "AF 1B B1 FA", {
      onMatch(address, size) {
        console.log("global-metadata.dat signature found at: " + address)
  
        let found = true;
        const EndOffset = address.add(0x8).readU32()
        let nextOffset = EndOffset;
        for (let offset = 0x8; offset < EndOffset; offset += 0x8) {
          const nowOffset = address.add(offset).readU32()
          console.log("Offset: ", nowOffset, " NextOffset: ", nextOffset)
          if (nowOffset !== nextOffset) {
            found = false
            break
          }
          nextOffset = nowOffset + address.add(offset + 4).readU32()
        }
        if (found) {
          const global_metadata_size = nextOffset
          if (global_metadata_size > 0x100) {
            console.log("Size: ", global_metadata_size)
  
            send("metadata", address.readByteArray(global_metadata_size))
          }
        }
      }
    })
  }
}

const il2cppSymbol = {
  il2cpp_domain_get: ["pointer", []],//93
  il2cpp_domain_get_assemblies: ["pointer",["pointer","pointer"]],//95
  il2cpp_assembly_get_image: ["pointer",["pointer"]],//35
  il2cpp_image_get_class_count: ["size_t",["pointer"]],//269
  il2cpp_image_get_class: ["pointer",["pointer","int"]],//270
  il2cpp_class_is_generic: ["bool",["pointer"]],//40
  il2cpp_class_from_name: ["pointer",["pointer","pointer","pointer"]],//46
  il2cpp_class_get_fields: ["pointer",["pointer","pointer"]],//50
  il2cpp_class_get_properties: ["pointer",["pointer","pointer"]],//53
  il2cpp_class_get_methods: ["pointer",["pointer","pointer"]],//56
  il2cpp_class_get_method_from_name: ["pointer",["pointer","pointer","int"]],//57
  il2cpp_class_get_type: ["pointer",["pointer"]],//73

  il2cpp_get_corlib: ["pointer",[]],//17
  il2cpp_method_get_object: ["pointer",["pointer","pointer"]],//162
  il2cpp_method_is_generic: ["bool",["pointer"]],//163
  il2cpp_object_get_virtual_method: ["pointer",["pointer","pointer"]],//197
  il2cpp_runtime_invoke: ["pointer",["pointer","pointer","pointer","pointer"]],//213
  il2cpp_type_get_object: ["pointer",["pointer"]],//252
}

function il2cppMethod(namespace, className, method) {
  const mem = Memory.alloc(Math.max(namespace.length+className.length+1)+1, method.length)
  mem.writeUtf8String(namespace)
  mem.add(namespace.length+1).writeUtf8String(className)
  const klass = il2cpp_class_from_name(il2cpp_get_corlib(), mem, mem.add(namespace.length+1))
  mem.writeUtf8String(method)
  return il2cpp_class_get_method_from_name(klass, mem, 0)
}

// against libUnityPlugin.so.
// their names will be decrypted when [class,field,property,method] are accessed.
function il2cpp() {
  for (const [key, value] of Object.entries(il2cppSymbol)) {
      global[key] = new NativeFunction(libil2cpp.getExportByName(key), value[0], value[1])
  }
  const Type_GetGenericArguments = il2cppMethod("System", "Type", "GetGenericArguments")
  const MethodInfo_GetGenericArguments = il2cppMethod("System.Reflection", "MethodInfo", "GetGenericArguments")
  let method
  const iter = Memory.alloc(Process.pointerSize)
  const assemblies = il2cpp_domain_get_assemblies(il2cpp_domain_get(), iter)
  const size = iter.readU32()
  for (let i = 0; i < size; i++) {
      const assembly = assemblies.add(Process.pointerSize*i).readPointer()
      const image = il2cpp_assembly_get_image(assembly)
      const count = il2cpp_image_get_class_count(image)
      for (let ii = 0; ii < count; ii++) {
          const klass = il2cpp_image_get_class(image, ii)
          if (il2cpp_class_is_generic(klass)) {
              const type = il2cpp_type_get_object(il2cpp_class_get_type(klass))
              method = il2cpp_object_get_virtual_method(type, Type_GetGenericArguments)
              il2cpp_runtime_invoke(method, type, ptr(0), ptr(0))
          }
          iter.writePointer(ptr(0))
          while (true) {
              if (il2cpp_class_get_fields(klass, iter).isNull()) { break }
          }
          iter.writePointer(ptr(0))
          while (true) {
              if (il2cpp_class_get_properties(klass, iter).isNull()) { break }
          }
          iter.writePointer(ptr(0))
          while (true) {
              method = il2cpp_class_get_methods(klass, iter)
              if (method.isNull()) { break }
              if (il2cpp_method_is_generic(method)) {
                  const methodInfo = il2cpp_method_get_object(method, ptr(0))
                  method = il2cpp_object_get_virtual_method(methodInfo, MethodInfo_GetGenericArguments)
                  il2cpp_runtime_invoke(method, methodInfo, ptr(0), ptr(0))
              }
          }
      }
  }
}

const exp = Module.findExportByName(null, "il2cpp_domain_get")
if (exp === null) {
  dump()
} else {
  const libil2cpp = Process.getModuleByAddress(exp)
  il2cpp()
  dump()
}