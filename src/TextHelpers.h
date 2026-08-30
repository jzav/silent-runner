#pragma once

#include <cstddef>

#include <cstdint>
#include <string>
#include <vector>
#include <string_view>


namespace TextHelpers {
bool EqualsOrdinalIgnoreCase(
    std::wstring_view value,
    std::wstring_view expected
) noexcept;

bool StartsWith(
    std::string_view text,
    std::string_view prefix
) noexcept;
bool StartsWith(
    std::wstring_view text,
    std::wstring_view prefix
) noexcept;

bool EndsWith(
    std::string_view text,
    std::string_view suffix
) noexcept;
bool EndsWith(
    std::wstring_view text,
    std::wstring_view suffix
) noexcept;


char ToUpperAscii(char ch) noexcept;
std::string ToUpperAsciiCopy(std::string s);

wchar_t ToUpperAscii(wchar_t ch) noexcept;
std::wstring ToUpperAsciiCopy(std::wstring s);

std::string Utf16ToUtf8(const std::wstring& text);
uint64_t PayloadByteCountFromBytes(const std::vector<char>& bytes) noexcept;
std::string PayloadBase64FromBytes(const std::vector<char>& bytes);

void AppendJsonEscaped(std::string& out, const std::string& value);
void AppendJsonStringField(std::string& out, const char* name, const std::string& value);
void AppendJsonWideStringField(std::string& out, const char* name, const std::wstring& value);
void AppendJsonBoolField(std::string& out, const char* name, bool value);
void AppendJsonUInt64Field(std::string& out, const char* name, uint64_t value);

void ReplaceAll(
    std::string& text,
    std::string_view from,
    std::string_view to
);

// Converts one canonical compact JSON object into LF-separated
// "fieldName":value records in a single pass.
bool TryTokenizeCanonicalJsonObject(std::string& text);
bool TryReadLine(
    std::string_view text,
    std::size_t& position,
    std::string_view& line
) noexcept;



bool TryParseJsonStringField(
    std::string_view text,
    std::size_t& position,
    const char* name,
    std::string& value
);
bool TryParseJsonWideStringField(
    std::string_view text,
    std::size_t& position,
    const char* name,
    std::wstring& value
);
bool TryParseJsonBoolField(
    std::string_view text,
    std::size_t& position,
    const char* name,
    bool& value
);
bool TryParseJsonUInt64Field(
    std::string_view text,
    std::size_t& position,
    const char* name,
    uint64_t& value
);



void AppendTxtStringField(std::string& out, const char* name, const std::string& value);
void AppendTxtUpperStringField(std::string& out, const char* name, const std::string& value);
void AppendTxtWideStringField(std::string& out, const char* name, const std::wstring& value);
void AppendTxtUpperWideStringField(std::string& out, const char* name, const std::wstring& value);
void AppendTxtBoolField(std::string& out, const char* name, bool value);
void AppendTxtUpperBoolField(std::string& out, const char* name, bool value);

void AppendTxtUInt64Field(std::string& out, const char* name, uint64_t value);

bool TryParseTxtStringField(
    std::string_view field,
    const char* name,
    std::string& value
);
bool TryParseTxtWideStringField(
    std::string_view field,
    const char* name,
    std::wstring& value
);
bool TryParseTxtBoolField(
    std::string_view field,
    const char* name,
    bool& value
);
bool TryParseTxtUInt64Field(
    std::string_view field,
    const char* name,
    uint64_t& value
);






} // namespace TextHelpers
