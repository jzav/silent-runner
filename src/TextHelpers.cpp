#include "TextHelpers.h"

#include <climits>
#include <limits>
#include <utility>


#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace {

bool ConsumeJsonFieldPrefix_(
    std::string_view text,
    std::size_t& position,
    const char* name
) {

    if (!name) {
        return false;
    }

    std::string token;
    token.reserve(std::char_traits<char>::length(name) + 3);
    token += "\"";
    token += name;
    token += "\":";

    if (text.compare(position, token.size(), token) != 0) {
        return false;
    }

    position += token.size();
    return true;
}


int HexDigitValue_(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

bool ReadJsonHex4_(
    std::string_view text,
    std::size_t& position,
    uint32_t& value
) noexcept {
    if (position > text.size() ||
        text.size() - position < 4) {
        return false;
    }

    uint32_t parsed = 0;

    for (std::size_t i = 0; i < 4; ++i) {
        const int digit = HexDigitValue_(text[position + i]);
        if (digit < 0) {
            return false;
        }

        parsed =
            (parsed << 4) |
            static_cast<uint32_t>(digit);
    }

    position += 4;
    value = parsed;
    return true;
}

bool AppendUtf8CodePoint_(
    std::string& value,
    uint32_t codePoint
) {
    if (codePoint <= 0x7f) {
        value.push_back(static_cast<char>(codePoint));
        return true;
    }

    if (codePoint <= 0x7ff) {
        value.push_back(
            static_cast<char>(0xc0 | (codePoint >> 6))
        );
        value.push_back(
            static_cast<char>(0x80 | (codePoint & 0x3f))
        );
        return true;
    }

    if (codePoint >= 0xd800 && codePoint <= 0xdfff) {
        return false;
    }

    if (codePoint <= 0xffff) {
        value.push_back(
            static_cast<char>(0xe0 | (codePoint >> 12))
        );
        value.push_back(
            static_cast<char>(
                0x80 | ((codePoint >> 6) & 0x3f)
            )
        );
        value.push_back(
            static_cast<char>(0x80 | (codePoint & 0x3f))
        );
        return true;
    }

    if (codePoint <= 0x10ffff) {
        value.push_back(
            static_cast<char>(0xf0 | (codePoint >> 18))
        );
        value.push_back(
            static_cast<char>(
                0x80 | ((codePoint >> 12) & 0x3f)
            )
        );
        value.push_back(
            static_cast<char>(
                0x80 | ((codePoint >> 6) & 0x3f)
            )
        );
        value.push_back(
            static_cast<char>(0x80 | (codePoint & 0x3f))
        );
        return true;
    }

    return false;
}

bool ParseJsonStringValue_(
    std::string_view text,
    std::size_t& position,
    std::string& value
) {

    if (position >= text.size() || text[position] != '"') {
        return false;
    }

    std::string parsed;
    ++position;

    while (position < text.size()) {
        const unsigned char ch =
            static_cast<unsigned char>(text[position++]);

        if (ch == '"') {
            value = std::move(parsed);
            return true;
        }

        if (ch < 0x20) {
            return false;
        }

        if (ch != '\\') {
            parsed.push_back(static_cast<char>(ch));
            continue;
        }

        if (position >= text.size()) {
            return false;
        }

        const char escaped = text[position++];

        switch (escaped) {
            case '"': parsed.push_back('"'); break;
            case '\\': parsed.push_back('\\'); break;
            case '/': parsed.push_back('/'); break;
            case 'b': parsed.push_back('\b'); break;
            case 'f': parsed.push_back('\f'); break;
            case 'n': parsed.push_back('\n'); break;
            case 'r': parsed.push_back('\r'); break;
            case 't': parsed.push_back('\t'); break;

            case 'u': {
                uint32_t codePoint = 0;
                if (!ReadJsonHex4_(
                        text,
                        position,
                        codePoint
                    )) {
                    return false;
                }

                if (codePoint >= 0xd800 &&
                    codePoint <= 0xdbff) {
                    if (position > text.size() ||
                        text.size() - position < 6 ||
                        text[position] != '\\' ||
                        text[position + 1] != 'u') {
                        return false;
                    }

                    position += 2;

                    uint32_t lowSurrogate = 0;
                    if (!ReadJsonHex4_(
                            text,
                            position,
                            lowSurrogate
                        ) ||
                        lowSurrogate < 0xdc00 ||
                        lowSurrogate > 0xdfff) {
                        return false;
                    }

                    codePoint =
                        0x10000 +
                        ((codePoint - 0xd800) << 10) +
                        (lowSurrogate - 0xdc00);
                }

                if (!AppendUtf8CodePoint_(
                        parsed,
                        codePoint
                    )) {
                    return false;
                }
                break;
            }

            default:
                return false;
        }
    }

    return false;
}

bool Utf8ToUtf16_(
    const std::string& text,
    std::wstring& value
) {
    if (text.empty()) {
        value.clear();
        return true;
    }

    if (text.size() >
        static_cast<std::size_t>(
            std::numeric_limits<int>::max()
        )) {
        return false;
    }

    const int requiredCharacterCount =
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            nullptr,
            0
        );

    if (requiredCharacterCount <= 0) {
        return false;
    }

    std::wstring parsed(
        static_cast<std::size_t>(requiredCharacterCount),
        L'\0'
    );

    const int writtenCharacterCount =
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            text.data(),
            static_cast<int>(text.size()),
            parsed.data(),
            requiredCharacterCount
        );

    if (writtenCharacterCount != requiredCharacterCount) {
        return false;
    }

    value = std::move(parsed);
    return true;
}

bool ParseTxtStringFieldValue_(
    std::string_view field,
    const char* name,
    std::string& value
) {
    if (!name ||
        field.size() < 3 ||
        field.front() != '[' ||
        field.back() != ']') {
        return false;
    }

    std::string prefix;
    prefix.reserve(std::char_traits<char>::length(name) + 2);
    prefix += "[";
    prefix += name;
    prefix += "=";

    if (!TextHelpers::StartsWith(field, prefix) ||
        field.size() < prefix.size() + 1) {

        return false;
    }

    const std::string_view parsedValue =
        field.substr(
            prefix.size(),
            field.size() - prefix.size() - 1
        );

    value.assign(
        parsedValue.data(),
        parsedValue.size()
    );
    return true;
}



bool TryParseUInt64Text_(
    std::string_view text,
    uint64_t& value
) noexcept {

    if (text.empty()) {
        return false;
    }

    uint64_t parsed = 0;

    for (char ch : text) {
        if (ch < '0' || ch > '9') {
            return false;
        }

        const unsigned digit =
            static_cast<unsigned>(ch - '0');

        if (parsed >
            (std::numeric_limits<uint64_t>::max() - digit) /
                10) {
            return false;
        }

        parsed = parsed * 10 + digit;
    }

    value = parsed;
    return true;
}

} // namespace


namespace TextHelpers {
bool EqualsOrdinalIgnoreCase(
    std::wstring_view value,
    std::wstring_view expected
) noexcept {
    if (value.size() > static_cast<std::size_t>(INT_MAX) ||
        expected.size() > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }

    if (value.empty() || expected.empty()) {
        return value.empty() && expected.empty();
    }

    return CompareStringOrdinal(
        value.data(),
        static_cast<int>(value.size()),
        expected.data(),
        static_cast<int>(expected.size()),
        TRUE
    ) == CSTR_EQUAL;
}

bool StartsWith(
    std::string_view text,
    std::string_view prefix
) noexcept {
    return
        text.size() >= prefix.size() &&
        text.compare(0, prefix.size(), prefix) == 0;
}

bool StartsWith(
    std::wstring_view text,
    std::wstring_view prefix
) noexcept {
    return
        text.size() >= prefix.size() &&
        text.compare(0, prefix.size(), prefix) == 0;
}

bool EndsWith(
    std::string_view text,
    std::string_view suffix
) noexcept {
    return
        text.size() >= suffix.size() &&
        text.compare(
            text.size() - suffix.size(),
            suffix.size(),
            suffix
        ) == 0;
}

bool EndsWith(
    std::wstring_view text,
    std::wstring_view suffix
) noexcept {
    return
        text.size() >= suffix.size() &&
        text.compare(
            text.size() - suffix.size(),
            suffix.size(),
            suffix
        ) == 0;
}


void ReplaceAll(
    std::string& text,
    std::string_view from,
    std::string_view to
) {
    if (from.empty() || from == to) {
        return;
    }

    std::string result;
    result.reserve(text.size());

    std::size_t pos = 0;

    while (pos < text.size()) {

        if (pos + from.size() <= text.size() &&
            std::string_view(text.data() + pos, from.size()) == from)
        {
            result.append(to);
            pos += from.size();
        }
        else {
            result.push_back(text[pos]);
            ++pos;
        }
    }

    text.swap(result);
}

bool TryTokenizeCanonicalJsonObject(
    std::string& text
) {
    if (text.size() < 2 ||
        text.front() != '{' ||
        text.back() != '}')
    {
        return false;
    }

    std::string result;
    result.reserve(text.size() - 2);

    std::size_t pos = 1;
    const std::size_t end = text.size() - 1;

    while (pos < end) {

        if (pos + 2 <= end &&
            text[pos] == ',' &&
            text[pos + 1] == '"')
        {
            result.push_back('\n');
            result.push_back('"');
            pos += 2;
        }
        else {
            result.push_back(text[pos]);
            ++pos;
        }
    }

    text.swap(result);
    return true;
}
bool TryReadLine(
    std::string_view text,
    std::size_t& position,
    std::string_view& line
) noexcept {
    if (position >= text.size()) {
        line = {};
        return false;
    }

    const std::size_t lineEnd = text.find('\n', position);

    if (lineEnd == std::string_view::npos) {
        line = text.substr(position);
        position = text.size();
        return true;
    }

    line = text.substr(position, lineEnd - position);
    position = lineEnd + 1;
    return true;
}

char ToUpperAscii(char ch) noexcept {
    if (ch >= 'a' && ch <= 'z') {
        return static_cast<char>(ch - ('a' - 'A'));
    }

    return ch;
}

std::string ToUpperAsciiCopy(std::string s) {
    for (auto& ch : s) {
        ch = ToUpperAscii(ch);
    }

    return s;
}

wchar_t ToUpperAscii(wchar_t ch) noexcept {
    if (ch >= L'a' && ch <= L'z') {
        return static_cast<wchar_t>(ch - (L'a' - L'A'));
    }

    return ch;
}

std::wstring ToUpperAsciiCopy(std::wstring s) {
    for (auto& ch : s) {
        ch = ToUpperAscii(ch);
    }

    return s;
}

std::string Utf16ToUtf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }

    const int requiredByteCount = WideCharToMultiByte(
        CP_UTF8,
        0,
        text.c_str(),
        static_cast<int>(text.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (requiredByteCount <= 0) {
        return {};
    }

    std::string bytes(static_cast<size_t>(requiredByteCount), '\0');

    const int writtenByteCount = WideCharToMultiByte(
        CP_UTF8,
        0,
        text.c_str(),
        static_cast<int>(text.size()),
        bytes.data(),
        requiredByteCount,
        nullptr,
        nullptr
    );

    if (writtenByteCount <= 0) {
        return {};
    }

    return bytes;
}

uint64_t PayloadByteCountFromBytes(const std::vector<char>& bytes) noexcept {
    return static_cast<uint64_t>(bytes.size());
}

std::string PayloadBase64FromBytes(const std::vector<char>& bytes) {
    static constexpr char kBase64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= bytes.size()) {
        const uint32_t triple =
            (static_cast<uint32_t>(static_cast<unsigned char>(bytes[i])) << 16) |
            (static_cast<uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8) |
            static_cast<uint32_t>(static_cast<unsigned char>(bytes[i + 2]));

        out.push_back(kBase64[(triple >> 18) & 0x3f]);
        out.push_back(kBase64[(triple >> 12) & 0x3f]);
        out.push_back(kBase64[(triple >> 6) & 0x3f]);
        out.push_back(kBase64[triple & 0x3f]);

        i += 3;
    }

    const size_t remaining = bytes.size() - i;
    if (remaining == 1) {
        const uint32_t triple =
            static_cast<uint32_t>(static_cast<unsigned char>(bytes[i])) << 16;

        out.push_back(kBase64[(triple >> 18) & 0x3f]);
        out.push_back(kBase64[(triple >> 12) & 0x3f]);
        out.push_back('=');
        out.push_back('=');
    } else if (remaining == 2) {
        const uint32_t triple =
            (static_cast<uint32_t>(static_cast<unsigned char>(bytes[i])) << 16) |
            (static_cast<uint32_t>(static_cast<unsigned char>(bytes[i + 1])) << 8);

        out.push_back(kBase64[(triple >> 18) & 0x3f]);
        out.push_back(kBase64[(triple >> 12) & 0x3f]);
        out.push_back(kBase64[(triple >> 6) & 0x3f]);
        out.push_back('=');
    }

    return out;
}

void AppendJsonEscaped(std::string& out, const std::string& value) {
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (ch < 0x20) {
                    static constexpr char kHex[] = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(kHex[(ch >> 4) & 0x0f]);
                    out.push_back(kHex[ch & 0x0f]);
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
}

void AppendJsonStringField(std::string& out, const char* name, const std::string& value) {
    out += "\"";
    out += name;
    out += "\":\"";
    AppendJsonEscaped(out, value);
    out += "\"";
}

void AppendJsonWideStringField(std::string& out, const char* name, const std::wstring& value) {
    AppendJsonStringField(out, name, Utf16ToUtf8(value));
}

void AppendJsonBoolField(std::string& out, const char* name, bool value) {
    out += "\"";
    out += name;
    out += "\":";
    out += value ? "true" : "false";
}

void AppendJsonUInt64Field(std::string& out, const char* name, uint64_t value) {
    out += "\"";
    out += name;
    out += "\":";
    out += std::to_string(value);
}

bool TryParseJsonStringField(
    std::string_view text,
    std::size_t& position,
    const char* name,
    std::string& value
) {

    std::size_t parsedPosition = position;
    std::string parsed;

    if (!ConsumeJsonFieldPrefix_(
            text,
            parsedPosition,
            name
        ) ||
        !ParseJsonStringValue_(
            text,
            parsedPosition,
            parsed
        )) {
        return false;
    }

    position = parsedPosition;
    value = std::move(parsed);
    return true;
}

bool TryParseJsonWideStringField(
    std::string_view text,
    std::size_t& position,
    const char* name,
    std::wstring& value
) {

    std::size_t parsedPosition = position;
    std::string parsed;
    std::wstring parsedWide;

    if (!TryParseJsonStringField(
            text,
            parsedPosition,
            name,
            parsed
        ) ||
        !Utf8ToUtf16_(
            parsed,
            parsedWide
        )) {
        return false;
    }

    position = parsedPosition;
    value = std::move(parsedWide);
    return true;
}

bool TryParseJsonBoolField(
    std::string_view text,
    std::size_t& position,
    const char* name,
    bool& value
) {

    std::size_t parsedPosition = position;

    if (!ConsumeJsonFieldPrefix_(
            text,
            parsedPosition,
            name
        )) {
        return false;
    }

    bool parsed = false;

    if (text.compare(parsedPosition, 4, "true") == 0) {
        parsed = true;
        parsedPosition += 4;
    } else if (text.compare(parsedPosition, 5, "false") == 0) {
        parsedPosition += 5;
    } else {
        return false;
    }

    position = parsedPosition;
    value = parsed;
    return true;
}

bool TryParseJsonUInt64Field(
    std::string_view text,
    std::size_t& position,
    const char* name,
    uint64_t& value
) {
    std::size_t parsedPosition = position;

    if (!ConsumeJsonFieldPrefix_(
            text,
            parsedPosition,
            name
        )) {
        return false;
    }

    const std::size_t valueStart = parsedPosition;

    while (parsedPosition < text.size() &&
           text[parsedPosition] >= '0' &&
           text[parsedPosition] <= '9') {
        ++parsedPosition;
    }

    if (parsedPosition == valueStart) {
        return false;
    }

    uint64_t parsed = 0;

    if (!TryParseUInt64Text_(
            text.substr(
                valueStart,
                parsedPosition - valueStart
            ),
            parsed
        )) {
        return false;
    }

    position = parsedPosition;
    value = parsed;
    return true;
}



void AppendTxtStringField(
    std::string& out,
    const char* name,
    const std::string& value
) {
    out += "[";
    out += name;
    out += "=";
    out += value;
    out += "]";
}

void AppendTxtUpperStringField(
    std::string& out,
    const char* name,
    const std::string& value
) {
    AppendTxtStringField(out, name, ToUpperAsciiCopy(value));
}

void AppendTxtWideStringField(
    std::string& out,
    const char* name,
    const std::wstring& value
) {
    AppendTxtStringField(out, name, Utf16ToUtf8(value));
}

void AppendTxtUpperWideStringField(
    std::string& out,
    const char* name,
    const std::wstring& value
) {
    AppendTxtWideStringField(out, name, ToUpperAsciiCopy(value));
}

void AppendTxtBoolField(
    std::string& out,
    const char* name,
    bool value
) {
    out += "[";
    out += name;
    out += "=";
    out += value ? "true" : "false";
    out += "]";
}

void AppendTxtUpperBoolField(
    std::string& out,
    const char* name,
    bool value
) {
    AppendTxtStringField(out, name, value ? "TRUE" : "FALSE");
}


void AppendTxtUInt64Field(
    std::string& out,
    const char* name,
    uint64_t value
) {
    out += "[";
    out += name;
    out += "=";
    out += std::to_string(value);
    out += "]";
}

bool TryParseTxtStringField(
    std::string_view field,
    const char* name,
    std::string& value
) {
    std::string parsed;

    if (!ParseTxtStringFieldValue_(
            field,
            name,
            parsed
        )) {
        return false;
    }

    value = std::move(parsed);
    return true;
}

bool TryParseTxtWideStringField(
    std::string_view field,
    const char* name,
    std::wstring& value
) {
    std::string parsed;
    std::wstring parsedWide;

    if (!TryParseTxtStringField(
            field,
            name,
            parsed
        ) ||
        !Utf8ToUtf16_(
            parsed,
            parsedWide
        )) {
        return false;
    }

    value = std::move(parsedWide);
    return true;
}

bool TryParseTxtBoolField(
    std::string_view field,
    const char* name,
    bool& value
) {
    std::string parsed;

    if (!TryParseTxtStringField(
            field,
            name,
            parsed
        )) {
        return false;
    }

    parsed = ToUpperAsciiCopy(
        std::move(parsed)
    );

    if (parsed == "TRUE") {
        value = true;
        return true;
    }

    if (parsed == "FALSE") {
        value = false;
        return true;
    }

    return false;
}

bool TryParseTxtUInt64Field(
    std::string_view field,
    const char* name,
    uint64_t& value
) {
    std::string parsed;
    uint64_t parsedValue = 0;

    if (!TryParseTxtStringField(
            field,
            name,
            parsed
        ) ||
        !TryParseUInt64Text_(
            parsed,
            parsedValue
        )) {
        return false;
    }

    value = parsedValue;
    return true;
}

} // namespace TextHelpers
