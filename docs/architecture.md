# AVRA — Arxitektura taklifi (v0.1)

Nov 4, 2026

> Bu fayl loyihaning to'liq arxitektura hujjatidan eksport qilingan
> nusxa (diagrammalarsiz). Jonli, diagrammali versiyasi va holat
> belgilari (status dropdown'lar):
> https://claude.ai/artifact/EjJM4ZHNMHN3BoDgsS7qyb
>
> 10-bo'limdagi "Holat" ustuni shu eksport paytidagi holatni
> ko'rsatadi. Yakuniy, rasmiy qaror yozuvi —
> `docs/decisions/0001-initial-architecture-decisions.md`.

## 1. Vizyonni tushunishim

AVRA oddiy skaner emas: u xavfsizlik tadqiqotchisining yordamchi hamkori bo'lishi kerak. U maqsadni tushunadi, reja tuzadi, vositalarni qat'iy chegarada ishlatadi va topilmani isbot bilan hisobotga aylantiradi.

Brifdan olgan asosiy tushunchalarim:

- **Nima:** Claude Opus 5.5 ning fikrlash qobiliyatini xavfsiz vositalar va qat'iy ish jarayoni (workflow) bilan birlashtiruvchi modulli tadqiqot platformasi.
- **Kimga:** avval yakka tadqiqotchilar va bug bounty ovchilari, keyin pentest kompaniyalari, banklar va fintech jamoalari.
- **Farqi:** Nmap'ni o'rab turgan skript yoki buyruqlar ketma-ketligi emas. Asosiy qiymat gipoteza yaratish, tekshirish, soxta signallarni (false positive) kamaytirish va isbotni saqlashda.
- **Asosiy tamoyil:** gumon qilingan zaiflik avtomatik ravishda tasdiqlangan zaiflikka aylanmaydi. Tasdiqlash alohida, ruxsat bilan boshqariladigan bosqich.
- **Chegara:** faqat ruxsat berilgan (authorized) muhitda ishlaydi. AI modelga operatsion tizimga cheksiz kirish berilmaydi.

Brifdagi muhim farqni ham qayd etaman: Claude Code bizning dasturlash yordamchimiz, Claude Opus 5.5 API esa AVRA ilovasining ichidagi fikrlash dvigateli. Ular alohida tizim, alohida hisob va alohida to'lov.

Vizyon keng, lekin birinchi versiya (MVP) uning faqat kichik, to'liq ishlaydigan bir qismini bajaradi. Bu 3-bo'limda aniq belgilangan.

## 2. Arxitektura taklifi

Tavsiya etilgan arxitektura uch zonaga bo'lingan: Windows hostdagi AVRA yadrosi, laboratoriya VM'lari va tashqi Claude API. Model hech qachon shell'ga to'g'ridan-to'g'ri tegmaydi.

&#91;embedded content: AVRA arxitekturasi · uch zona, ruxsat va ma'lumot oqimi\]

Har bir harakat Policy qatlamidan o'tadi. Runner esa Orchestrator'ga ishonmay, scope'ni o'zi ham qayta tekshiradi.

### Modullar va ularning chegaralari

Brifdagi modullar MVP'da quyidagi amaliy qismlarga birlashtirildi. Reasoning va Research alohida xizmat emas: ikkalasi ham Claude'ga so'rov yuboradigan bosqichlar, shuning uchun bitta ish jarayonida turadi.

| Modul | Vazifasi | Brif bo'limi |
| --- | --- | --- |
| Orchestrator | Sessiya, holatlar mashinasi, budjet, qadamlar chegarasi, qayta urinishlar | 4.1 |
| Policy | Scope, harakat darajasi, tasdiq, rate limit, kill switch | 4.9 |
| LLM Gateway | Provider abstraksiyasi, Claude adapteri, sarf hisobi | 4.2 |
| Tool Engine va Runner | Tipli vositalar, argument tekshiruvi, Kali VM'da ijro, tuzilgan natija | 4.4 |
| Recon | Nmap, HTTP metadata, texnologiyani aniqlash. Vosita to'plami va ish bosqichi | 4.3 |
| Research | Gipoteza va dalil modellari, Claude yordamidagi bosqich | 4.5 |
| Verification | Xavfsiz tekshiruvlar va ishonch darajasi. Holat qoidalari kodda, modelda emas | 4.6 |
| Storage | SQLite, dalil ombori, audit log. Bilim bazasi keyinroq | 4.7 |
| Reporting | Markdown va JSON hisobot | 4.8 |

### Bir sessiya yo'li

1. Siz sessiya yaratasiz va scope faylini ko'rsatasiz.
2. Policy nishonni scope bo'yicha tekshiradi.
3. Orchestrator Recon bosqichini boshlaydi: Claude vosita so'raydi, Policy ruxsat beradi, Runner bajaradi.
4. Natija tuzilmaga keltiriladi va xom chiqish bilan birga saqlanadi.
5. Claude natijani tahlil qilib, dalilga bog'langan gipotezalar yozadi.
6. Verification tekshiruv rejasini tuzadi. Intruziv harakat home-lab scope'dan tashqarida bo'lsa, sizdan tasdiq so'raladi; home-lab scope ichida bo'lsa, tasdiqsiz davom etadi (§8a).
7. Tekshiruv natijasi holat va ishonch darajasi bilan topilmaga aylanadi.
8. Reporting hisobot tuzadi.

### Joylashuv variantlari

| Variant | Afzalligi | Kamchiligi |
| --- | --- | --- |
| A. Hammasi Windows hostda | Eng sodda, dasturlash qulay | Vositalar izolyatsiyasiz, Linux vositalari cheklangan |
| B. Hammasi Kali VM ichida | To'liq izolyatsiya, vositalar tayyor | Dasturlash VM ichida noqulay, RAM sarfi yuqori, kod va API kalit VM'da turadi |
| C. Gibrid: yadro Windows'da, Runner Kali'da (tavsiya) | Izolyatsiya va qulay dasturlash birga, Runner kichik va tekshiriladigan | Ikki qism va aloqa kanalini yozish va himoyalash kerak |

## 3. MVP doirasi

MVP bitta laboratoriya nishoni (Juice Shop), bitta foydalanuvchi va buyruq satri orqali ishlaydigan to'liq tadqiqot sikli bo'ladi. Brifdagi 10 qadamning hammasi unda bor, lekin har biri eng kichik ishlaydigan ko'rinishda.

| Qism | MVP'da bor | MVP'da yo'q (keyinroq) |
| --- | --- | --- |
| Interfeys | Buyruq satri (CLI) | Veb-panel |
| Nishon | Faqat laboratoriyadagi Juice Shop | Boshqa ilovalar, haqiqiy tizimlar |
| Recon | Cheklangan Nmap profili, HTTP metadata, texnologiyani aniqlash, oddiy endpoint topish | Chuqur API discovery, subdomain, DNS tahlili |
| Zaiflik turlari | 1-2 ta: ochiq katalog (security misconfiguration) va login'dagi SQL injection | XSS, SSRF, IDOR, access control, business logic |
| AI model | Claude Opus 5.5, provider abstraksiyasi orqali | Ollama, ixtisoslashgan modellar |
| Agentlar | Bitta orchestrator, ketma-ket bosqichlar | Multi-agent ish jarayonlari |
| Xotira | Sessiya va dalillar SQLite va fayllarda saqlanadi | Versiyalangan bilim bazasi, o'tgan tadqiqotdan foydalanish |
| Xavfsizlik | Scope allowlist, tasdiq darajalari, audit log, kill switch, rate limit | Izolyatsiyalangan konteynerlar, ko'p foydalanuvchi, SSO |
| Hisobot | Markdown va JSON | PDF, HTML, mijoz shablonlari |
| Foydalanuvchi | Faqat siz | Jamoa, API, enterprise |

MVP muvaffaqiyat mezonlari (hammasi tekshiriladigan bo'lishi kerak):

1. Bitta buyruq bilan sessiyadan hisobotgacha ishlaydi.
2. Kamida bitta ma'lum Juice Shop zaifligi topiladi, xavfsiz tekshiriladi va dalili saqlanadi.
3. Scope tashqarisidagi nishonga urinish avtomatik testlarda rad etiladi.
4. Har bir harakat audit logda, har bir sessiyaning xarajati hisobotda ko'rinadi.
5. Hisobotdagi har bir da'vo dalilga bog'langan; tasdiqlanmagan topilma tasdiqlangan deb yozilmaydi.
6. Bir xil sinov bir necha marta takrorlanib, natijalar ulushi o'lchanadi. Bu o'lchov, kafolat emas.

MVP maqsadi mahsulot chiqarish emas, g'oyaning ishlashini isbotlash. Shu sababli veb-panel, ko'p agentlilik va local modellar ataylab chetda qoldirilgan.

## 4. Realistik yo'l xaritasi

MVP taxminan 12-17 hafta ichida, beshta bosqichda quriladi. Har bosqich shlyuz mezoni bajarilmaguncha yopilmaydi, keyingisi esa sizning tasdig'ingizdan keyin boshlanadi.

&#91;embedded content: yo'l xaritasi · 8 bosqich, 5 ta MVP shlyuzi\]

Muddatlar taxminiy va ish tezligingiz hamda sinov natijalariga bog'liq. MVP'dan keyingi bosqichlarning tartibi MVP natijasiga qarab qayta ko'rib chiqiladi.

## 5. Texnik xatarlar va realistik bo'lmagan kutilmalar

Eng katta xatar texnologiyaning o'zi emas, ishonchlilik va xavfsizlik: model noto'g'ri xulosani ishonch bilan aytishi mumkin, nishondagi matn esa modelga buyruq bermoqchi bo'lishi mumkin.

| Xatar | Nega muhim | Qarshi chora |
| --- | --- | --- |
| Soxta topilmalar (false positive) | Model noto'g'ri xulosani ishonchli ohangda yozishi mumkin | Topilma dalilsiz yaratilmaydi. «Tasdiqlangan» holatni model emas, Verification Engine'ning aniq tekshiruvi qo'yadi |
| Prompt injection | Nishon sahifasi yoki vosita chiqishidagi matn modelga buyruq bermoqchi bo'lishi mumkin | Vosita chiqishi doim ishonchsiz ma'lumot sifatida o'raladi. Harakatga ruxsatni model emas, tashqi policy qatlami beradi |
| Scope'dan chiqib ketish | Redirect, DNS o'zgarishi yoki IP va hostname chalkashligi boshqa tizimga tegib ketishiga olib kelishi mumkin | Har harakat oldidan manzil qayta hal qilinib tekshiriladi. Runner tarmog'i faqat laboratoriyaga ochiq bo'ladi |
| Xarajatning nazoratdan chiqishi | Agent sikli uzun chiqishlarni qayta-qayta yuborib hisobni oshirishi mumkin | Sessiya budjeti, qadamlar chegarasi, xom chiqishni modelga emas, saqlashga yo'naltirish |
| Takrorlanmaslik | Bir xil sinov har safar boshqacha yo'l tutishi mumkin | Model versiyasini qotirish, to'liq prompt va javoblarni yozib borish, yozib olingan javoblar bilan test (replay) |
| Qurilma resurslari | 16 GB RAM'da Windows, VM'lar va Docker birga siqiladi. Docker Desktop (WSL2/Hyper-V) VirtualBox'ni sekinlashtirishi mumkin | Juice Shop'ni Ubuntu VM ichidagi Docker'da yurgizish, bir vaqtda bitta VM, RAM'ni 32 GB gacha kengaytirish |
| Vosita chiqishini tahlil qilish | Vositalarning chiqish formati turlicha va o'zgaruvchan | Har bir vosita uchun adapter, XML/JSON chiqishni afzal ko'rish, xavfsiz parserlar |
| Modelning rad etishi | Claude ba'zi xavfsizlik so'rovlarini rad etishi yoki cheklashi mumkin | Buni normal natija sifatida qayd etamiz va aylanib o'tishga urinmaymiz. Ruxsat etilgan scope kontekstini aniq beramiz |
| Maxfiylik | Nishon ma'lumotlari tashqi API'ga yuboriladi. Banklar uchun bu to'siq bo'lishi mumkin | Yuborishdan oldin sirlarni yashirish (redaction), keyinroq self-hosted variant |
| Qamrovning kengayib ketishi | Hamma narsani birdan qurish natijasiz loyihaga olib keladi | Faqat 3-bo'limdagi MVP, har bosqichdan keyin sizning tasdig'ingiz |

### Realistik bo'lmagan kutilmalar

- **O'tgan tadqiqotdan o'rganadi.** Model sessiyalardan o'z vaznlarini o'zgartirmaydi. Birinchi versiyada bu qidiriladigan eslatmalar va dalillar bazasi, haqiqiy o'rganish emas.
- **Chuqur tadqiqot va yangi zaifliklar.** MVP laboratoriyada ma'lum zaiflik turlarini topadi. Noma'lum (0-day) zaiflikni topish tadqiqot darajasidagi masala, uni kafolatlab bo'lmaydi.
- **Business logic zaifliklari.** Ular ilovaning ma'nosini tushunishni talab qiladi va avtomatlashtirish uchun eng qiyin. Keyingi bosqichlarga qoldiramiz.
- **Local model Opus o'rnini bosadi.** RTX 4060 (8 GB VRAM) da faqat kichik, siqilgan modellar ishlaydi. Murakkab fikrlashda ular Opus'dan sezilarli past, shuning uchun yordamchi rolda qoladi.
- **Opus 5.5 hamma narsaga ishlatiladi.** Bu qimmat. Oddiy ishlar (parsing, filtrlash) LLM'siz oddiy kod bilan bajariladi. Arzonroq modelga yo'naltirish alohida qaror (10-bo'lim).
- **Tijorat tayyorligi.** Bank va enterprise uchun mustaqil xavfsizlik auditi, yuridik shartlar va ishonchlilik o'lchovlari kerak. Bu MVP'dan ancha keyin.
- **Yakka tezlik.** To'liq vizyon (multi-agent, enterprise, dashboard) odatda jamoa va yillar masalasi. Yakka va AI yordamida bosqichma-bosqich boriladi.
- **Dasturlash bilimi.** Har qatorni tushunishingiz shart emas, lekin arxitektura va xavfsizlik qarorlarini tushunishingiz shart. Shuning uchun har qadamdan keyin oddiy tushuntirish va tekshirish yo'li beriladi.

## 6. Texnologiya steki

Stek Python atrofida qurilgan va qaramliklar ataylab kam saqlangan. Hozircha hech narsa o'rnatilmagan, bu faqat taklif; versiyalarni 0-bosqichda o'rnatishdan oldin tekshiramiz.

| Qatlam | Taklif | Nega | Alternativa |
| --- | --- | --- | --- |
| Til | Python 3.12 | Xavfsizlik vositalari va Anthropic SDK ekotizimi eng boy, o'rganish oson | Go, TypeScript |
| Ma'lumot modellari | Pydantic v2 | Vosita chaqiruvlari, topilmalar va scope uchun qat'iy sxema va tekshiruv | dataclasses |
| AI integratsiya | Rasmiy anthropic SDK | Tool use, sarf hisobi va qayta urinishlar tayyor | O'z HTTP mijozimiz (keraksiz murakkab) |
| Buyruq satri | Typer | Kam kod, tushunarli yordam matnlari | argparse (qaramliksiz, lekin ko'proq kod) |
| Saqlash | SQLite va diskdagi dalil fayllari (SHA-256 bilan) | Server kerak emas, zaxira oson, keyinroq FTS5 bilan qidirish mumkin | PostgreSQL (ko'p foydalanuvchi bosqichida) |
| Tool Runner | Kali VM'dagi kichik FastAPI xizmati, token bilan himoyalangan | Har vosita uchun tipli so'rov, model shell qatorini tuzmaydi | SSH (kamroq kod, lekin buyruq qatori xavfi bor) |
| HTTP recon | httpx | Timeout va proxy ustidan to'liq nazorat | requests |
| Xavfsiz parser | defusedxml | Nmap XML chiqishini zararli kontentdan himoya qiladi | Standart xml |
| Test | pytest va yozib olingan LLM javoblari | API xarajatisiz takroriy testlar | - |
| Kod sifati | ruff, pip-audit | Bitta tez vosita va qaramlik zaifliklarini tekshirish | black va flake8 |
| Log va audit | Standart logging va hash zanjirli JSONL audit logi | Qo'shimcha qaramliksiz, o'zgartirishni aniqlash mumkin | structlog |
| Hisobot | Jinja2 shablonlari, Markdown va JSON chiqish | Shablonni kodga tegmay o'zgartirish | Qo'lda satr yig'ish |
| Sirlar | Windows Credential Manager (keyring) yoki muhit o'zgaruvchisi | API kalit repoga tushmaydi | - |
| Versiyalash | Git, private GitHub repo, ADR hujjatlari | Qarorlar tarixi saqlanadi | - |

Veb-panel uchun keyinroq Runner bilan bir stek (FastAPI va oddiy frontend) tanlanadi, lekin bu MVP'da yo'q.

## 7. Loyiha papkalar tuzilmasi

Tuzilma har bir modulga o'z papkasini beradi va xavfsizlik qatlami (policy) hamda Tool Runner'ni model kodidan alohida saqlaydi.

```
avra/
├── README.md
├── pyproject.toml
├── .gitignore
├── .env.example            # kalit nomlari, qiymatlarsiz
├── docs/
│   ├── architecture.md
│   ├── decisions/          # ADR-0001-... qaror yozuvlari
│   ├── security.md
│   └── lab-setup.md
├── src/avra/
│   ├── core/               # Orchestrator, sessiya, holatlar mashinasi
│   ├── llm/                # Provider abstraksiyasi, Claude adapteri, xarajat hisobi
│   ├── prompts/            # Versiyalangan prompt fayllari
│   ├── policy/             # Scope, tasdiq darajalari, rate limit, kill switch
│   ├── tools/              # Tipli vosita ta'riflari va adapterlar (nmap, http)
│   ├── recon/              # Recon bosqichi
│   ├── research/           # Gipoteza modellari va mantiqi
│   ├── verification/       # Tekshiruvlar, ishonch darajalari
│   ├── knowledge/          # Bilim bazasi (MVP'da minimal)
│   ├── reporting/          # Shablonlar va renderlar
│   ├── storage/            # SQLite, dalil ombori, audit log
│   ├── schemas/            # Umumiy Pydantic modellari
│   └── cli/                # Buyruq satri
├── runner/                 # Kali VM'ga o'rnatiladigan mustaqil xizmat
├── lab/                    # Laboratoriya sozlamasi: tarmoq, Juice Shop
├── scope/                  # Namuna scope fayllari (haqiqiy nishonlarsiz)
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/           # Scope, injection, kill switch testlari
│   └── fixtures/           # Yozib olingan LLM va vosita javoblari
└── data/                   # Git'ga kirmaydi: sessiyalar, dalillar, baza
```

Uchta qaror shu tuzilmani belgilaydi. Birinchidan, `runner/` alohida turadi, chunki u Kali VM'da kam qaramlik bilan mustaqil ishlashi kerak. Ikkinchidan, `policy/` modeldan ajratilgan, shunda uni mustaqil testlash mumkin va model kodi uni chetlab o'ta olmaydi. Uchinchidan, `data/` Git'ga kirmaydi, chunki dalillarda maxfiy ma'lumot bo'lishi mumkin.

Modul chegaralari yakuniy emas: `recon`, `research` va `verification` boshida bitta ish jarayonining bosqichlari sifatida boshlanishi mumkin va faqat zarurat tug'ilganda ajratiladi.

## 8. Dastlabki xavfsizlik arxitekturasi

Asosiy qoida oddiy: model taklif qiladi, tashqi kod ruxsat beradi, hamma narsa yozib boriladi. Ishonchli qismlar: siz, Orchestrator va policy qatlami. Ishonchsiz qismlar: modelning takliflari, vosita chiqishi, nishon kontenti va bilim bazasidagi eski yozuvlar.

### Harakat darajalari

| Daraja | Misol | Ruxsat |
| --- | --- | --- |
| Passiv | Oddiy GET so'rovlar, sahifa metadatasi | Scope ichida avtomatik |
| Faol-xavfsiz | Cheklangan Nmap profili, sekin crawl | Scope ichida, rate limit bilan, sessiya boshida bir marta tasdiqlanadi |
| Intruziv | Payload bilan tekshiruv (masalan, SQL injection tekshiruvi) | Home-lab scope'dan tashqarida — har safar sizning tasdig'ingiz: nima, qayerga va qanday xavf bilan ko'rsatiladi. Home-lab scope ichida — tasdiqsiz, to'liq audit bilan (§8a) |
| Buzuvchi | Ma'lumotni o'chirish yoki o'zgartirish, xizmatni to'xtatish, ommaviy parol tanlash | MVP'da taqiqlangan |

### Himoya qatlamlari

| Himoya | MVP'da | Keyinroq |
| --- | --- | --- |
| Ruxsat va scope | YAML scope fayli: nishon, portlar, ruxsat etilgan vositalar va harakat darajalari, amal qilish muddati. Standart holat taqiq. Tekshiruv ikki joyda: Orchestrator'da va Runner'ning o'zida | Imzolangan scope, mijoz ruxsatnomasini biriktirish |
| Tarmoq izolyatsiyasi | Kali VM faqat host-only laboratoriya tarmog'ida, internetga chiqmaydi | Har sessiya uchun alohida konteyner |
| Tipli vositalar va minimal imtiyoz | Shell yo'q: Runner argumentlar ro'yxati bilan ishga tushiradi, argumentlar allowlist bilan tekshiriladi, timeout va chiqish hajmi chegaralangan. Oddiy foydalanuvchi huquqida, Nmap connect-scan bilan boshlanadi | Resurs cheklovlari (cgroup), alohida xizmat hisoblari |
| Inson tasdig'i | Home-lab scope'dan tashqaridagi intruziv harakat oldidan CLI'da aniq harakat, nishon va xavf ko'rsatilib so'raladi. Home-lab scope ichida so'ralmaydi — ruxsatni scope fayli beradi (§8a) | Jamoa uchun rol asosidagi tasdiq |
| Audit log | Faqat qo'shiladigan, hash zanjirli JSONL: prompt, vosita so'rovi, natija xeshi, tasdiq qarori | Tashqi o'zgarmas saqlash va eksport |
| Kill switch | `avra kill` va Ctrl+C: Orchestrator to'xtaydi, Runner jarayonlarni o'chiradi, aloqa uzilsa Runner o'zi to'xtaydi | Veb-paneldan global to'xtatish |
| Rate limit va budjet | Nishonga so'rov tezligi va parallellik chegarasi, qadam va token budjeti | Nishon va foydalanuvchi bo'yicha kvotalar |
| Sirlar | API kalit Credential Manager yoki muhit o'zgaruvchisida, loglarda yashiriladi, .env Git'ga kirmaydi, alohida kalit va oylik limit | Maxsus sirlar ombori |
| Prompt injection | Vosita chiqishi chegaralangan blokda ishonchsiz ma'lumot sifatida beriladi, undagi ko'rsatmalar bajarilmaydi. Har harakat scope va daraja bo'yicha tashqi tekshiruvdan o'tadi. Bilim bazasi yozuvlari ham ma'lumot, ko'rsatma emas | Alohida tekshiruvchi model, injection testlar to'plami |
| Zararli vosita chiqishi | Xavfsiz parserlar (defusedxml), hajm chegarasi, hisobotda matnni escape qilish, chiqishni hech qachon bajarmaslik | Sandbox'da tahlil |
| Qaramliklar | Versiyalar qotiriladi, pip-audit bilan tekshiriladi | SBOM, imzolangan relizlar |

AVRA ruxsatsiz nishonga tegmaydi va modelning xavfsizlik cheklovlarini aylanib o'tishga urinmaydi. Bu qoidalar sinov (tests/security) bilan himoyalanadi.

### 8a. Progressive Autonomy va Capability-First tamoyili

Yuqoridagi ikki jadval endi bir aniqlik bilan to'ldiriladi: tasdiq talabi harakat darajasiga **va** nishon qayerda ekaniga bog'liq.

**Capability-First tamoyili.** AVRA'ga avtonomiya ambient ishonch sifatida emas, faqat aniq va cheklangan **capability** sifatida beriladi. Capability — scope faylidagi aniq yozuv: qaysi nishon, qaysi portlar, qaysi vositalar, qaysi harakat darajalari ruxsat etilgan. Scope faylida yozilmagan narsa standart holatda taqiqlanganligicha qoladi — bu o'zgarmaydi. Boshqacha aytganda, avtonomiya darajasi "model qanchalik ishonchli" degan narsaga emas, unga berilgan aniq capability'ga bog'liq.

**Progressive Autonomy modeli (ikki holatli, hozircha scoring'siz).** Bitta scope fayli aniq ravishda **home-lab scope** deb belgilanishi mumkin (hozircha yagona nomzod: `scope/example.scope.yaml`dagi Juice Shop nishoni, `docs/lab-setup.md`). Shu belgi bilan:

- Scope ruxsat bergan passiv, faol-xavfsiz va intruziv harakatlar har bir qadam uchun alohida tasdiqsiz davom etadi.
- Hamma narsa baribir to'liq audit qilinadi (audit log o'zgarmagan).
- Buzuvchi (destructive) daraja baribir taqiqlangan — bu hech qachon avtomatik ochilmaydi, home-lab ichida ham.

Scope fayli home-lab deb belgilanmagan bo'lsa (har qanday boshqa nishon, jumladan kelajakda qo'shilishi mumkin bo'lgan real tarmoq) — eski qoida to'liq kuchda qoladi: intruziv harakat har safar sizning aniq tasdig'ingizni talab qiladi, va bu avvalgi tasdiqni keyingisiga "blanket consent" sifatida hech qachon eslab qolmaydi.

**Amalga oshirish holati (muhim):** yuqoridagi — rasmiy qabul qilingan siyosat (`docs/decisions/0001-...md`, 13-band), lekin kod hali yo'q. Phase 1 faqat scope validatsiyasi va auditni qamrab oldi; home-lab belgisini scope sxemasiga qo'shish va Policy qatlamida haqiqatan tekshirish — Policy qatlamiga tegadigan o'zgarish, shuning uchun CLAUDE.md Working protocol bo'yicha alohida tasdiq va o'z increment'i sifatida amalga oshiriladi (ehtimol Phase 2, Tool Runner bilan birga).

Bu — alohida, hali loyihalanmagan g'oyadan farq qiladi: vaqt o'tishi va muvaffaqiyatli urinishlar soni asosida ko'proq avtonomiya ("graduated trust" / "track record"). Progressive Autonomy — shunchaki ikki holatli kalit (home-lab ichida / tashqarisida); u hali hech qanday ishonch balli yoki statistika hisoblamaydi va ishlatmaydi. Graduated trust g'oyasi `docs/decisions/0001-...md`da "hali loyihalanmagan" deb alohida qayd etilgan va shunday qoladi.

O'zgarmaydigan narsalar: scope chegaralari (default-deny), audit log, kill switch, xarajat/budjet limitlari, va home-lab scope'dan tashqaridagi har qanday faol/intruziv tekshiruv uchun tasdiq talabi.

## 9. Claude Opus 5.5 API integratsiya strategiyasi

AVRA'da Claude Opus 5.5 qaror qabul qiluvchi emas, taklif beruvchi: u vosita chaqiruvini so'raydi, ruxsatni esa tashqi kod beradi.

| Qatlam | Nima qiladi | Nima qila olmaydi |
| --- | --- | --- |
| Claude Opus 5.5 | Tahlil, gipoteza, keyingi qadamni taklif qilish, tushuntirish | Buyruq ijro etish, scope'ni o'zgartirish, topilmani tasdiqlangan deb belgilash |
| Orchestrator | Bosqichlar, budjet va qadamlar chegarasini boshqarish | Ruxsat qarorini chetlab o'tish |
| Policy qatlami | Scope, tasdiq darajasi va rate limitni tekshirish | Modelga bo'ysunish |
| Tool Runner | Tasdiqlangan, tipli so'rovni bajarish | Ixtiyoriy buyruq bajarish |

- **Abstraksiya.** `LLMProvider` interfeysi bitta `complete()` chaqiruvini beradi: kirishda xabarlar, tool ta'riflari va budjet, chiqishda matn, tool so'rovlari va sarf hisobi. Birinchi realizatsiya `ClaudeProvider`; Ollama va boshqalar keyinroq shu interfeysga ulanadi.
- **Model nomi.** U konfiguratsiyada turadi va kodga qotirilmaydi (API identifikatori taxminan `claude-opus-5-5`). Aniq nomni kodlashdan oldin docs.claude.com'da tekshiramiz.
- **Tool use.** Har vosita JSON sxemali tool sifatida ta'riflanadi. Model so'rov qaytaradi, u Pydantic va policy tekshiruvidan o'tmaguncha bajarilmaydi. Natija modelga ishonchsiz ma'lumot sifatida o'ralib qaytariladi.
- **Strukturali natija.** Gipoteza va topilmalar `record_hypothesis` va `record_finding` kabi tool'lar orqali sxemaga mos keladi, erkin matnni qayta tahlil qilmaymiz. Har topilma dalil ID'lariga bog'lanadi.
- **Agent sikli.** Siklni model emas, Orchestrator boshqaradi: Recon, Tahlil, Gipoteza, Tekshiruv rejasi, Tekshiruv, Hisobot. Har bosqichda faqat unga ruxsat etilgan tool'lar va qadam hamda token chegarasi bo'ladi.
- **Kontekst.** Xom chiqish diskka yoziladi, modelga qisqa normallashtirilgan yozuv va dalil ID'si beriladi. Prompt caching imkoniyatini hujjatdan tekshirib, o'lchab ishlatamiz.
- **Xarajat.** Har chaqiruvdan keyin kirish va chiqish tokenlari, kesh va narx yoziladi (narxlar jadvali konfiguratsiyada, qo'lda yangilanadi). Sessiya budjetiga yetilsa, tizim to'xtaydi. Hisobotda sessiya xarajati ko'rinadi. Anthropic Console'da AVRA uchun alohida API kalit va oylik limit qo'yiladi.
- **Ishonchlilik.** Rate limit va yuklanish xatolarida kutib qayta urinish (exponential backoff), timeout, har qadamdan keyin holatni saqlash. Uzilgan sessiyani davom ettirish mumkin bo'ladi.
- **Takrorlanuvchanlik.** Model identifikatori, parametrlar va prompt versiyasi har chaqiruv bilan yoziladi. Testlar yozib olingan javoblar bilan API xarajatisiz ishlaydi.
- **Rad etish.** Model so'rovni rad etsa yoki cheklasa, bu normal natija: qayd etiladi va foydalanuvchiga ko'rsatiladi. Rad etishni aylanib o'tishga urinmaymiz.
- **Maxfiylik.** Modelga yuborishdan oldin sirlar (parol, token, cookie) yashiriladi.

## 10. Sizning tasdig'ingizni talab qiladigan qarorlar

Davom etishdan oldin quyidagi 12 qaror sizning tasdig'ingizni kutmoqda; har birining holatini jadvalda belgilang.

| № | Qaror mavzusi | Mening tavsiyam | Alternativa | Holat |
| --- | --- | --- | --- | --- |
| 1 | Joylashuv | Orchestrator Windows'da, Tool Runner Kali VM'da (gibrid) | Hammasi Kali ichida yoki hammasi Windows'da | Muhokama kerak |
| 2 | Runner transporti | Tipli HTTP xizmat (FastAPI) | SSH | Tasdiqlandi |
| 3 | Til va interfeys | Python 3.12, Pydantic, Typer, MVP'da faqat CLI | Veb-panelni darhol qurish | Tasdiqlandi |
| 4 | Saqlash | SQLite va dalil fayllari | PostgreSQL | Tasdiqlandi |
| 5 | Agent boshqaruvi | Orchestrator holatlar mashinasi, model faqat bosqich ichida qaror qiladi | Modelga to'liq erkin sikl berish | Tasdiqlandi |
| 6 | Model siyosati | Opus 5.5 yagona fikrlash modeli, oddiy ishlar LLM'siz. Arzonroq modelga yo'naltirish faqat sizning roziligingiz bilan, keyinroq | Boshidanoq arzonroq modelni aralashtirish | Muhokama kerak |
| 7 | Harakat darajalari | To'rt daraja, intruziv harakat har safar tasdiqlanadi | Barcha faol harakatlarni avtomatik bajarish | Tasdiqlandi |
| 8 | Birinchi zaifliklar | Ochiq katalog va login'dagi SQL injection | XSS yoki boshqa tur | Tasdiqlandi |
| 9 | Laboratoriya | Host-only tarmoq, Juice Shop Ubuntu VM ichidagi Docker'da (Windows'da Docker Desktop'siz) | Docker Desktop Windows'da | Muhokama kerak |
| 10 | Xarajat siyosati | Sessiya budjeti, alohida API kalit va oylik limit. Summani siz belgilaysiz | Limitsiz ishlash (tavsiya etilmaydi) | Tasdiqlandi |
| 11 | Operativ xotira | 32 GB ga kengaytirish | 16 GB bilan bir vaqtda bitta VM | Tasdiqlandi |
| 12 | Keyingi qadam | 0-bosqich: laboratoriya va Git repo skeleti | Darhol dastur kodidan boshlash | Muhokama kerak |
|  |  |  |  |  |

Hech qaysi qaror tasdiqlanmaguncha kod yozilmaydi va qo'shimcha dependency o'rnatilmaydi.
