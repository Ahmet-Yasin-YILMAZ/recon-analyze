recon-analyzer
Bug bounty / pentest recon çıktılarını (subdomain listeleri, URL'ler, nuclei/sqlmap/XSStrike/JWT/trufflehog/feroxbuster sonuçları) tek bir klasörden okuyup, kanıt kalitesine göre (evidence quality, bağımsız kaynak korelasyonu, confidence, impact, exploitability, false-positive penalty) skorlayan ve önceliklendirilmiş bir Markdown rapor üreten tek dosyalık bir bash script'i.
Neden
Recon araçları onbinlerce satırlık ham çıktı üretir. Bunların hepsini elle gezip "burada gerçekten önemli bir şey var mı" sorusuna cevap bulmak zaman alır. Bu script, farklı araçların çıktılarını tek bir "bulgu ailesi" (finding family) altında birleştirip, her aile için 0-100 arası bir risk skoru ve P0-P3 öncelik etiketi üretir.
Kullanım
bash
chmod +x recon_analyze.sh
./recon_analyze.sh
Çalıştırınca analiz edilecek klasörün yolunu soracak. Klasördeki tüm dosyaları tarayıp <klasör>/RECON_REPORT.md dosyasını oluşturur.
Skorlama metodolojisi
Recon dosyaları → Normalizasyon → Kanıt çıkarımı → Bulgu ailesi gruplama
→ Bağımsız kaynak korelasyonu → Confidence → Impact → Exploitability
→ Exposure → False-positive penalty → Risk skoru → Karar / sıradaki adım
Confidence: kanıtın ne kadar güçlü olduğunu gösterir (örn. sqlmap'in kendi çıktısı %92, feroxbuster'ın path tahmini %55).
Risk skoru: bulgu doğruysa potansiyel etki + istismar edilebilirlik + exposure + kanıt gücü + korelasyon bonusu − yanlış pozitif cezası.
Bağımsız kaynak sayımı, dosya adına değil araç adına göre yapılır — örneğin ferox_suspicious.txt ve ferox_interesting.txt aynı feroxbuster taramasından geldiği için tek kaynak sayılır, yapay olarak güven puanını şişirmez.
Skor	Öncelik
90–100	P0
75–89	P1
50–74	P2
1–49	P3
Hangi dosyaları tanır
Dosya adı kalıbı	Kategori
sqlmap_summary.txt, sqlmap_results.txt	SQL Injection
xsstrike_results.txt	XSS
jwt_analysis.txt	JWT / IDOR
nuclei_critical_high.txt, nuclei_results.txt	Nuclei (statik CVE/misconfig)
nuclei_dast_all.jsonl	Nuclei DAST
ferox_suspicious.txt, ferox_interesting.txt	Dizin/dosya fuzzing
thog_swagger, thog_github, *trufflehog*	Secret taraması (verified/unverified ayrımı yapılır)
subdomains*.txt	Subdomain listesi
gau_filtered.txt, *katana_urls_inscope*	URL listesi
Statik/ikili dosyalar (.jpg .png .css .js vb.) ve ham/debug dosyalar (*.log, katana_raw.jsonl vb.) baştan filtrelenir.
Bilinmeyen dosyalar ne olur
Tanıma iki katmanlıdır:
Dosya adı eşleşmesi (yukarıdaki tablo) — en güvenilir yöntem, doğrudan kategoriye atar.
İçerik bazlı yedek tanıma — isim eşleşmezse, .txt uzantılı dosyalar için içeriğin ilk satırına bakılır:
sqlmap identified the following injection point ile başlıyorsa → SQLi
İlk 5 satırda Efficiency: 100 varsa → XSS
http:// veya https:// ile başlıyorsa → URL listesi
Bir domain formatına (alan-adi.com gibi) uyuyorsa → subdomain listesi
Bu iki katmandan hiçbiri eşleşmezse, dosya "Sınıflandırılamayan dosyalar" bölümüne düşer ve raporun sonunda açıkça listelenir — script hiçbir veriyi sessizce atmaz, tanıyamadığı her şeyi "elle bak" diye işaretleyip görünür tutar. .txt olmayan ve hiçbir isim kalıbına uymayan dosyalar (örn. .json, .csv, uzantısız) içerik kontrolüne hiç girmeden doğrudan bu listeye gider.
Rapor formatı
Her bulgu için:
Confidence, status (SUSPECTED / CORRELATED / NEEDS_MANUAL_VALIDATION), severity
Impact / exploitability / exposure / evidence strength / correlation bonus / false-positive penalty ayrı ayrı gösterilir
Etkilenen endpoint listesi — ilk 20 URL doğrudan raporda listelenir, kalan sayı belirtilir
Bilinen sınırlamalar ve önemli uyarı
⚠️ feroxbuster'ın recursive/derin fuzzing modu, gerçek olmayan iç içe path kombinasyonları (.git/.hg/.idea/...) üretebilir. Bu script bu tür sonuçları da diğerleri gibi "Dotfile" kategorisinde raporlar — script bunları otomatik ayırt etmez. Yüzlerce/binlerce endpoint içeren bir "Dotfile" bulgusuyla karşılaşırsanız:
Önce hedefin wildcard response verip vermediğini kontrol edin (rastgele bir path'e istek atıp 200 dönüp dönmediğine bakın).
Wildcard yoksa bile, path'lerin gerçekçi olup olmadığını (%3f, %ff gibi encode kalıntıları, mantıksız iç içe klasör isimleri) gözden geçirin.
Küçük gruplardaki (1-15 endpoint) bulgular genellikle daha güvenilirdir.
Bu script hiçbir bulguyu otomatik doğrulamaz — "SUSPECTED" ve "NEEDS_MANUAL_VALIDATION" etiketli her şey, rapor edilmeden önce curl ile elle test edilmelidir. Bu araç bir triyaj/önceliklendirme aracıdır, bir zafiyet tarayıcısı değildir.
Lisans
Serbestçe kullanabilir, değiştirebilir ve dağıtabilirsiniz.
