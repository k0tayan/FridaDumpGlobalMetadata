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
