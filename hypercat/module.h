#ifndef MODULE_H
#define MODULE_H

class CModule
{
public:
	struct ModuleSections_t
	{
		ModuleSections_t(void) = default;
		ModuleSections_t(const string& svSectionName, uintptr_t pSectionBase, size_t nSectionSize) :
			m_svSectionName(svSectionName), m_pSectionBase(pSectionBase), m_nSectionSize(nSectionSize) {}

		bool IsSectionValid(void) const
		{
			return m_nSectionSize != 0;
		}

		string    m_svSectionName;           // Name of section.
		uintptr_t m_pSectionBase{};          // Start address of section.
		size_t    m_nSectionSize{};          // Size of section.
	};

	CModule(void) = default;
	CModule(const string& moduleName, std::uintptr_t moduleBase);
	CMemory FindPatternSIMD(const uint8_t* szPattern, const char* szMask, ModuleSections_t moduleSection = {}) const;
	CMemory FindPatternSIMD(const string& svPattern, ModuleSections_t moduleSection = {}) const;
	CMemory FindString(const string& string, const ptrdiff_t occurence = 1, bool nullTerminator = false) const;
	CMemory FindStringReadOnly(const string& svString, bool nullTerminator) const;

	CMemory          GetVirtualMethodTable(const std::string& tableName);
	CMemory          GetExportedFunction(const string& svFunctionName) const;
	ModuleSections_t GetSectionByName(const string& svSectionName) const;
	vector<ModuleSections_t> GetSections() const;
	uintptr_t        GetModuleBase(void) const;
	DWORD            GetModuleSize(void) const;
	string           GetModuleName(void) const;

	CMemory FindFreeDataPage(const size_t sizeWanted);
	void UnlinkFromPEB();

	ModuleSections_t         m_ExecutableCode;
	ModuleSections_t         m_ExceptionTable;
	ModuleSections_t         m_RunTimeData;
	ModuleSections_t         m_ReadOnlyData;
	IMAGE_NT_HEADERS64* m_pNTHeaders = nullptr;

private:
	string                   m_svModuleName;
	uintptr_t                m_pModuleBase{};
	DWORD                    m_nModuleSize{};
	IMAGE_DOS_HEADER*        m_pDOSHeader = nullptr;
	vector<ModuleSections_t> m_vModuleSections;
};

void GetModules();

inline unordered_map<std::string, CModule> g_sCachedModules = {}; // All modules we grab.

#endif // MODULE_H