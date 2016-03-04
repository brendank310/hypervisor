static uint64_t gdt_table[4];

inline uint64_t create_gdt_entry(uint32_t base, uint32_t limit, uint8_t type)
{
    uint64_t gdt_entry = 0;
    uint8_t *entry = (uint8_t*)&gdt_entry;



    return gdt_entry;
}

gdt::gdt(uint16_t size) : m_size(size), m_gdt(std::make_unique<uint64_t[]>(size))
{

}

void gdt::set_entry_base_address(uint16_t index, uint32_t address)
{
    uint8_t *entry = (uint8_t*)m_gdt[index];

    if(index >= m_size)
    {
        throw invalid_gdt_entry("GDT entry is out of range\n");
    }

    entry[7] = BA_TOP_MASK(address);
    entry[5] = BA_MID_MASK(address);
    entry[3] = BA_LOW_MASK1(address);
    entry[2] = BA_LOW_MASK0(address);
}

void gdt::set_entry_limit(uint16_t index, uint32_t limit)
{
    uint8_t *entry = (uint8_t*)m_gdt[index];

    if(index >= m_size)
    {
        throw invalid_gdt_entry("GDT entry is out of range\n");
    }

    // This is the Wrong Way(TM) to do this, we have to fetch
    // the flags in byte 6, and XOR them back into this byte
    entry[6] = LM_TOP(limit);

    
    entry[1] = LM_LOW1(limit);
    entry[0] = LM_LOW0(limit);
}

void gdt::set_granularity(uint16_t index, bool page_granular)
{

}

void gdt::set_mode_width(uint16_t index, bool mode_32bit)
{

}

void gdt::set_entry_present(uint16_t index, bool present)
{

}

void gdt::set_entry_privilege_level(uint16_t index, privilege_level level)
{

}

void gdt::set_entry_executable(uint16_t index, bool executable)
{

}

void gdt::set_entry_dc_bit(uint16_t index, bool bit)
{

}

void gdt::set_entry_readwrite(uint16_t index, bool readwrite)
{

}

void gdt::clear_entry_access(uint16_t index)
{

}

void gdt::add_gdt_entry(uint16_t index, uint32_t base, uint32_t limit, uint8_t type)
{
    // Lets edit the entry easily at a byte level
    uint8_t *entry = (uint8_t*)m_gdt[index];

    if(index >= m_size)
    {
        throw invalid_gdt_entry("GDT entry is out of range\n");
    }

    // Paging granularity
    entry[6] = 0xc0;

    entry[0] = limit & 0xff;
    entry[1] = (limit >> 8) & 0xff;
    entry[6] |= (limit >> 16) & 0xf;

    entry[2] = base & 0xff;
    entry[3] = (base >> 8) & 0xff;
    entry[4] = (base >> 16) & 0xff;
    entry[7] = (base >> 24) & 0xff;

    entry[5] = type;
}

void gdt::set_gdt_entry(uint16_t index, uint64_t entry_value)
{
    if(index >= m_size)
    {
        throw invalid_gdt_entry("GDT entry is out of range\n");
    }

    m_gdt[index] = entry_value;
}

uint64_t gdt::gdt_entry(uint16_t index)
{
    if(index >= m_size)
    {
        throw invalid_gdt_entry("GDT entry is out of range\n");
    }

    return m_gdt[index];
}