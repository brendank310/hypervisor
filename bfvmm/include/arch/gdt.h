
#ifndef GDT__H
#define GDT__H

// A GDT entry is laid out in a somewhat stupid fashion (I'm sure there
// were good reasons in 1992 that just cause us grief now). Anyhow, here
// is a little key for the diagram.
//     Base address portion of the entry
//     BA[X:Y] - Portion of the base address from its bits X to Y
//     
//     LM[X:Y] - Portion of the limit from its bits X to Y
//
//     FL[X:Y] - Portion of the flags from its bits X to Y
//
//     AB[X:Y] - Portion of the access bits from bits X to Y

//
// |----63<->56----|-<55-52>-|--<51-48>--|--<47-40>--|---<39-32>---|
// |   BA[31:24]   | FL[3:0] | LM[19:16] |  AB[7:0]  |  BA[23:16]  |
// |---------31<->16--------\-\----------|----------15<->0---------|
// |         BA[15:0]                    |         LM[15:0]        |
// |---------------------------------------------------------------|
// 
// The Base and limit are pretty self explanitory:
// base address + limit = memory range covered by the access byte and
// flag settings.
//
// The flags are as follows:
// FL[3] = Granularity bit  -- 0 is byte granular and 1 is small page (4KB) granular
// FL[2] = Size bit         -- 0 is 16b protected mode, 1 is 32b protected mode
// FL[1:0] = Unused         -- Processor reserved, not for use by software devs
//
// The access byte defines the following behavior:
// AB[7] = Present bit      -- Marks a GDT entry as valid and active
// AB[6:5] = Privilege bits -- Ring that the GDT is active for (3 = usermode, 0 = kernel)
// AB[4] = Unused           -- Processor reserved
// AB[3] = Executable bit   -- Marks a segment as executable
// AB[2] = Direction/Conforming bit -- 
//             If the executable bit is set:
//                  - A set bit indicates the code in the segment can executed in any privilege
//                    level equal to or less than the privilege level set by the privilege bits
//                  - An unset bit indicates the code is restricted to the privilege level set by
//                    privilege bits
//             Otherwise (data segment, not executable):
//                  - A set bit indicates the segment can grow upward in the address space
//                  - An unset bit indicates the segment can grow downwards
// AB[1] = Read Write bit -- If set, the segment is writable, otherwise read only
// AB[0] = Access bit     -- Set to 0, CPU will set to 1 if the segment is accessed
//

// Limit masks that operate on the proposed limit
#define LM_TOP_INT(x) ((x&0xF0000)>>16)
#define LM_LOW1_INT(x) ((x&0x0FF00)>>8)
#define LM_LOW0_INT(x) ((x&0x000FF)>>0)

// Limit macros that translate to the destination GDT format
#define LM_TOP(x) (LM_TOP_INT(x)<<48)
#define LM_LOW1(x) (LM_LOW1_INT(x)<<8)
#define LM_LOW0(x) (LM_LOW0_INT(x)<<0)

// Base address masks that operate on the actual address
#define BA_TOP_MASK_INT(x) ((0xFF000000&x)>>24)
#define BA_MID_MASK_INT(x) ((0x00FF0000&x)>>16)
#define BA_LOW_MASK1_INT(x) ((0x0000FF00&x)>>8)
#define BA_LOW_MASK0_INT(x) ((0x000000FF&x)>>0)

// Base address macros that translate a portion of the base
// address in its LSB form to its proper position for the 
// GDT entry
#define BA_TOP_MASK(x) (BA_TOP_MASK_INT(x)<<56)
#define BA_MID_MASK(x) (BA_MID_MASK_INT(x)<<32)
#define BA_LOW_MASK1(x) (BA_LOW_MASK1_INT(x)<<24)
#define BA_LOW_MASK0(x) (BA_LOW_MASK0_INT(x)<<16)

class gdt {
    enum privilege_level {
        ring_0 = 0,
        ring_1 = 1,
        ring_2 = 2,
        ring_3 = 3
    };

public:
    /// Constructor
    /// @param size Number of entries for the GDT
    ///
    gdt(uint16_t size = 4);

    /// Destructor
    ///
    virtual ~gdt() {}

    /* Base Address */

    /// Set the base address at a segment index
    ///
    /// @param index Segment to set the base address for
    /// @param addr Address to set as the base address for the segment
    ///
    void set_entry_base_address(uint16_t index, uint32_t address);

    /* Limit */

    /// Set the range for a segment
    ///
    /// @param index Segment to set the limit for
    /// @param limit Limit for the segment
    ///
    void set_entry_limit(uint16_t index, uint32_t limit);

    /* Flags */

    /// Set the segment granularity
    ///
    /// @param index Segment index to change granularity on
    /// @param page_granular True for page_granular, false for byte granular
    ///
    void set_granularity(uint16_t index, bool page_granular);

    /// Set the segment for 32bit protected mode
    ///
    /// @param index Segment index to set mode for
    /// @param mode_32bit True for 32b protected, false for 16b protected
    ///
    void set_mode_width(uint16_t index, bool mode_32bit);

    /* Access Byte */

    /// Set the entry active for the segment (AB[7])
    ///
    /// @param index Segment index to set activity
    /// @param preset True for active, false for inactive
    ///
    void set_entry_present(uint16_t index, bool present);

    /// Set the entry privilege level for the segment (AB[6:5])
    ///
    /// @param index Segment index to set privilege for
    /// @param level Privilege level
    ///
    void set_entry_privilege_level(uint16_t index, privilege_level level);

    /// Set the segment at index executable (AB[3])
    ///
    /// @param index Segment index to make executable
    /// @param executable True for executable, false for non-exec
    ///
    void set_entry_executable(uint16_t index, bool executable);

    /// Set the segment the DC bit (see above... AB[2])
    ///
    /// @param index Segment index to change DC bit
    /// @param bit set or unset
    ///
    void set_entry_dc_bit(uint16_t index, bool bit);

    /// Set the segment at index writable (AB[1])
    ///
    /// @param index Segment index to make RW/RO
    /// @param readwrite True for writable, false for readonly
    ///
    void set_entry_readwrite(uint16_t index, bool readwrite);

    /// Clear the segment access bit (AB[0])
    ///
    /// @param index Segment index to clear the access bit on
    ///
    void clear_entry_access(uint16_t index);

private:

    /// Create GDT Entry
    ///
    /// @param index Index of the GDT to add the entry to
    /// @param base  Base address of the segment
    /// @param limit Size of the segment 
    /// @param type  Permissions on the segment
    ///
    void add_gdt_entry(uint16_t index, uint32_t base, uint32_t limit, uint8_t type);

    /// Remove GDT Entry
    ///
    /// @param index Index of the GDT entry to remove
    /// 
    void remove_gdt_entry(uint16_t index);

    /// Set the GDT Entry at the given index
    ///
    /// @param index Index of the GDT entry to set
    /// @param entry_value The value of the entry to set
    ///
    void set_gdt_entry(uint16_t index, uint64_t entry_value);

    /// Get the GDT Entry at the given index
    ///
    /// @param index The entry to retrieve
    /// @return GDT entry
    ///
    uint64_t gdt_entry(uint16_t index);

    // Number of GDT entries
    uint16_t m_size;

    // The actual GDT that gets passed to the CPU
    // via the store GDT instruction
    std::unique_ptr<uint64_t> m_gdt;
};

#endif // GDT__H