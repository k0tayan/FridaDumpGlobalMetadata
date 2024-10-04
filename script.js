console.log("Searching global-metadata.dat in memory...")
for (const range of Process.enumerateRanges({protection: "r--", coalesce: true})) {
	Memory.scan(range.base, range.size, "AF 1B B1 FA", {
		onMatch(address, size){
			console.log("Metadata found at: " + address)

			let found = true;
			const EndOffset = address.add(0x8).readU32()
			let nextOffset = EndOffset;
			for (let offset = 0x8; offset < EndOffset; offset += 0x8) {
				const nowOffset = address.add(offset).readU32()
				if (nowOffset !== nextOffset) {
					found = false
					break
				}
				nextOffset = nowOffset + address.add(offset+4).readU32()
			}
			if (found){
				const DefinitionsOffset = EndOffset

				const DefinitionsCount = address.add(EndOffset-4).readU32()
				const global_metadata_size = DefinitionsOffset + DefinitionsCount
				console.log("Size: ", global_metadata_size)

				send("metadata", address.readByteArray(global_metadata_size))
			}
		}
	})
}
