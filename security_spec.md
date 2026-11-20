# Security Specification — Detektif Inferensial Cup (`/ruang/{kode}`)

## 1. Data Invariants
1. Dokumen ruang hanya boleh memakai ID 4 digit angka (`^[0-9]{4}$`).
2. `allow list` pada `/ruang` selalu ditolak (`false`) sehingga kode ruangan orang lain tidak bisa di-scrape.
3. Field `dibuatPada` bersifat abadi (*immutable*) setelah dibuat dan wajib bernilai `request.time`.
4. `pemenang` hanya boleh berpindah dari `null` ke `1 | 2 | 3 | 4` ketika `status == 'buka'`, dan wajib mengunci `status` menjadi `'terkunci'` serta mengisi `waktuMenang == request.time`.
5. Kelompok yang sedang bertanda `terkunciTim[tim] == true` tidak boleh memenangkan transaksi `pemenang`.
6. Pada mode `ujiCoba` (`ujiCoba.aktif == true`), HP kelompok hanya boleh mengubah status uji coba kelompoknya dari `false` ke `true` dan tidak boleh mereset hasil kelompok lain.
7. Tidak ada *ghost fields* yang diizinkan (`keys().hasOnly(...)` dan `affectedKeys().hasOnly(...)`).
8. Seluruh string (`namaTim`, `warnaTim`, `status`, `opsiTeks`) dibatasi ukuran maksimumnya agar kebal terhadap payload besar (*Denial of Wallet*).
9. Peta `opsiSalah` berkey tetap `'0'..'3'` bertipe boolean dan `opsiTeks` berkey tetap `'0'..'3'` bertipe string maksimal 300 karakter.
10. Field `pilihanHp` hanya boleh diubah saat `status == 'terkunci' && pemenang != null && modeTes == false`, dan indeks yang dipilih wajib memiliki `opsiSalah[idx] == false`.

## 2. Dirty Dozen Payloads (Harus Ditolak `PERMISSION_DENIED`)
1. `list('/ruang')`: Mencoba membaca seluruh daftar ruangan.
2. `get('/ruang/abc')`: ID ruangan bukan 4 digit.
3. `create('/ruang/1234', { status: 'buka' })`: Payload tidak lengkap dan `dibuatPada != request.time`.
4. `create('/ruang/1234', { ..., ghostField: true })`: Menyelipkan *shadow field*.
5. `create('/ruang/1234', { ..., namaTim: { '1': 'X'.repeat(200), ... } })`: Melebihi batas panjang nama tim (`<= 40`).
6. `create('/ruang/1234', { ..., status: 'buka', pemenang: 1 })`: Mencoba langsung membuat ruangan sudah ada pemenang.
7. `update('/ruang/1234', { pemenang: 4, status: 'terkunci', waktuMenang: request.time })` ketika `status == 'tutup'`: Menekan tombol sebelum guru membuka rebutan.
8. `update('/ruang/1234', { pemenang: 3, status: 'terkunci', waktuMenang: request.time })` ketika `pemenang == 1` sudah ada: Menimpa pemenang yang lebih cepat.
9. `update('/ruang/1234', { pemenang: 4, status: 'terkunci', waktuMenang: request.time })` ketika `terkunciTim['4'] == true`: Kelompok yang sudah salah pada soal itu mencoba merebut lagi.
10. `update('/ruang/1234', { pemenang: '4', status: 'terkunci' })`: *Value poisoning* (`pemenang` bertipe string bukan integer, tanpa `waktuMenang == request.time`).
11. `update('/ruang/1234', { ujiCoba: { aktif: true, hasil: { '1': false, '2': true, '3': false, '4': false } } })` saat `ujiCoba.aktif == false` dan `hasil['1'] == true`: Mencoba memalsukan atau mereset hasil uji coba saat tidak aktif.
12. `update('/ruang/1234', { dibuatPada: new Date(0) })`: Mencoba mengubah *immortal field* `dibuatPada`.
13. `update('/ruang/1234', { pilihanHp: 1 })` ketika `opsiSalah['1'] == true`: Mencoba memilih kembali opsi yang sudah dinonaktifkan karena salah.
14. `update('/ruang/1234', { pilihanHp: 0 })` ketika `status == 'buka'`: Mencoba memilih opsi sebelum ada kelompok yang memenangkan rebutan.
