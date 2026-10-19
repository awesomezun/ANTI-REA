[English](README_en.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](../../README.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · **Tiếng Việt** · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### Một MCP duy nhất bảo vệ tệp nhị phân, ứng dụng và logic cốt lõi khỏi sự phân tích của REA.

**Bạn có tính năng cốt lõi cần bảo vệ? Ngăn chặn việc phân tích và sao chép xuống tận cấp độ nhị phân.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#roadmap)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-Kagura_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Các công cụ dịch ngược như [REA](https://github.com/morluto/rea) cho phép tác tử (agent) mổ xẻ tệp nhị phân và viết lại đúng logic gốc chỉ bằng yêu cầu: *"Hãy phân tích cách tính năng này hoạt động trong ứng dụng đó và làm lại tương tự cho dự án của tôi"*.

**Tấn công bằng Agent? Vậy chúng tôi có Phòng thủ bằng Agent — lớp phòng thủ ngày càng mạnh hơn theo thời gian.** Mục tiêu cuối cùng của **ANTI-REA** là **chặn đứng mọi đối tượng và phương thức mà REA có thể phân tích**. Chỉ cần nói bằng ngôn ngữ tự nhiên với agent của bạn: **"Hãy bảo vệ logic cốt lõi của chương trình để REA không thể phân tích hay sao chép"**, agent sẽ tìm mã cốt lõi cùng các manh mối xung quanh, áp dụng làm rối (obfuscation) và ảo hóa (VM), kiểm tra xem tính năng gốc có bị lỗi không và đo tốc độ chạy đạt bao nhiêu phần trăm so với ban đầu.

Bạn không cần tự dựng môi trường実験 tấn công-phòng thủ phức tạp. **Mỗi ngày, chúng tôi đều cho PC phòng thủ đối đầu trực tiếp với PC tấn công REA riêng biệt để xem VM trên TestApp bị xuyên thủng ở đâu, vá lại điểm yếu và nâng cao sức phòng thủ.** Bạn chỉ việc kết nối ANTI-REA đã được tôi luyện mỗi ngày vào agent của mình.

---

## Sức mạnh phòng thủ hiện tại & Lộ trình (TestApp VM vs. Tấn công REA thực tế)

![TestApp VM Defense vs. REA 25%](../../docs/assets/defense-roadmap.svg)

Con số trên không phải tiến độ dự án trừu tượng, mà thể hiện **TestApp được bảo vệ bằng VM của chúng tôi trụ vững đến đâu trước cuộc tấn công trực tiếp từ REA trên máy khác**.

### Các giai đoạn tăng cường phòng thủ (Mục tiêu cuối cùng: Chặn mọi thứ REA phân tích)

- **25% (Hiện tại) · Chặn khôi phục tĩnh bước 1:** Đa dạng hóa handler và gắn kết ngữ cảnh toán hạng giúp ngăn phân tích tĩnh REA khôi phục công thức cốt lõi.
- **50% · Chặn phân tích tĩnh và suy luận ngữ cảnh xung quanh:** Ẩn các hàm phụ trợ trong dispatcher và manh mối trên đồ thị lời gọi.
- **75% · Phòng thủ theo dõi động và gỡ lỗi (Debugging):** Bảo vệ logic cốt lõi và hằng số trước trình gỡ lỗi, Frida, trace thực thi và dump bộ nhớ.
- **100% · Bảo vệ toàn diện mọi mục tiêu REA hỗ trợ:** Mở rộng từ tệp nhị phân gốc (C/C++, Rust, Go) sang .NET, Java/Kotlin, JavaScript/Electron, Python và macOS (Mach-O/ARM64).

---

## Bắt đầu nhanh

### 1. Cài đặt và kết nối Agent (`Set up your agent`)

Không cần tự gõ lệnh hay sửa file cấu hình, hãy bảo trực tiếp với agent của bạn (Claude Code, Cursor, Codex, Gemini CLI...):

```text
Cài đặt ANTI-REA vào môi trường ảo Python cục bộ (.venv) và kết nối máy chủ antirea.defense_mcp vào MCP để bạn có thể dùng ngay.
```

### 2. Ra lệnh bằng ngôn ngữ tự nhiên (`Ask your agent`)

```text
Hãy bảo vệ logic tính toán cốt lõi và các manh mối xung quanh trong dự án của tôi để REA không thể phân tích hay sao chép, đồng thời cho tôi biết tính năng gốc có hoạt động bình thường không và tốc độ chạy bằng bao nhiêu % so với ban đầu.
```

```text
Hãy lập kế hoạch bảo vệ app.exe bằng VMProtect và cho tôi xem trước, khi tôi duyệt thì thực thi.
```

### 3. Sử dụng trực tiếp từ Terminal (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Cách hoạt động & Vòng lặp đối kháng mỗi ngày

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## Các Engine hỗ trợ

Bên cạnh engine mã nguồn mở tích hợp sẵn (`Kagura + ANTI-REA`) đang mạnh lên mỗi ngày, **nếu bạn cần lớp bảo vệ mạnh hơn ngay lập tức, bạn có thể mua bản quyền Themida, VMProtect hoặc Code Virtualizer, kết nối với ANTI-REA và chỉ cần nói bằng ngôn ngữ tự nhiên cho agent biết mức hiệu năng thực thi và mức độ phòng thủ mà bạn mong muốn.**

```text
Hãy dùng VMProtect (hoặc Themida / Code Virtualizer) để giữ tốc độ chạy đạt trên 80% so với ban đầu trong khi bảo vệ logic cốt lõi ở mức tối đa.
```

| Engine | Connection | Status |
|---|---|---|
| **Kagura + ANTI-REA** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Phát triển & Kiểm thử

```powershell
python -m unittest discover -s tests -v
```

Dự án được phân phối theo giấy phép [MIT License](../../LICENSE) (các engine bảo vệ kết nối tuân theo giấy phép riêng của từng công cụ).
