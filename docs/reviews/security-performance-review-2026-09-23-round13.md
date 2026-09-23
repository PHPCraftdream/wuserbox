# Security and performance review — round 13 — P0–P3

## Вердикт и проверенный срез

**P0 — 0; P1 — 0; P2 — 1; P3 — 2. Release verdict: NO-GO по P2-1.**
Нового подтверждённого sandbox escape не найдено. Простой missing-source +
locked-destination сценарий round12 теперь останавливает Copy, а Clear
отказывает на неизвестной identity legacy alias. Однако новый трёхзначный
ответ теряется при повторном использовании alias memo; ниже приведён
статический путь к потере record. Квадратичное фильтрование children и
пересоздание canonical maps устранены, но повторные проходы по уже
канонизированным siblings сохраняют квадратичную CPU-работу.

Проверен **`fa5abf7034279d65bb5689d8ad8eed199be98e28`** в отдельном чистом
worktree; база сравнения — round12 и его `33dd8f405feca2ab675ee84c472a4d5ca454dec0`.
Период истории — **17–23 сентября 2026 включительно**, 232 достижимых коммита,
206 без merge. Просмотрены история изменений границы и текущие цепочки
account → stub → restricted token, ConPTY/conhost/Shield, relay/job/lease,
ACL/grant/revoke/links/path identity, profile copy/cleanup/Plan, check/audit,
CI/release. Каждый промежуточный коммит отдельно не исполнялся.

На контрольном чтении **23 сентября, 20:10 UTC** локальные HEAD/main и
GitHub main указывали на `fa5abf7`; достижимых локальных потомков этого SHA
не было. Изменений production после `fa5abf7` в проверенном срезе нет;
сам `fa5abf7` добавляет только checkpoint. Будущий коммит данного отчёта
не является новой проверенной версией production.

| Изменения недели | Что проверялось на итоговом коде |
| --- | --- |
| 17–18 сентября | OWNER RIGHTS, account ACE, hive inheritance, Unicode/canonical identity, hard-link preflight, ACL sweep и legacy accounts. |
| 19–20 сентября | Fail-closed identity/exit status, bridges, lease ownership, job-before-drain, own console/relay и reserved aliases. |
| 21–22 сентября | Conhost/thread shield, single-owner HPCON close, SID lifetime, bounded copy, reverse indexes, trustee memo и audit ACE order. |
| 23 сентября до round12 | Reserved ancestor aliases, Copy preflight, partial/terminal retraction, Plan ordering и nested prepareDir. |
| После round12, до HEAD | `3c9116c` — relay fixtures; `c33a81e` — unknown destination/reserved answers; `3032a34` — childAt, incremental canonical maps, persisted completeness. |

Локально: Go **1.26.0 windows/amd64**, **49 top-level tests PASS**, без FAIL
и SKIP. Использовались существующие адресные tests с небольшими временными
fixtures; реальные sandbox accounts, UAC, видимые окна, live ConPTY,
нагрузочные прогоны и benchmarks не запускались. Новых runtime probes для
находок ниже нет: их статическая доказательная база отделена от выполненных
tests. Production, тесты, workflow, зависимости и версии не изменялись.

## P0 — подтверждённых находок нет

Публичный run отказывает account-less sandbox и берёт lease до заполнения
profile (`internal/cli/setup/run.go:51`, `:72`, `:78`). Account stub создаётся
suspended, получает job, lease и ограниченный process DACL до resume
(`internal/win/proc/logon.go:1084`, `:1128`, `:1133`, `:1154`). Stub закрывает
birth conhost, создаёт restricted token, подготавливает console и выполняет
Shield до запуска команды (`internal/sandbox/exec/stub.go:165`, `:168`,
`:222`, `:254`). Restricted child тоже присоединяется к job до resume
(`internal/win/proc/run.go:232`).

`internal/win/token/restricted.go` сохраняет `DISABLE_MAX_PRIVILEGE`, полный
restricted check и ограниченный список SID. Собственная identity в AsSandbox
принадлежит sandbox account; путь Restricted не добавляет identity оператора.
Go-owned user/logon/read-group buffers удерживаются через native call.
Пути исполнения команды под unrestricted token в просмотренной цепочке нет.

## P1 — подтверждённых находок нет

| Участок | Evidence и граница вывода |
| --- | --- |
| Shield/conhost | Default DACL будущих threads меняется до process DACL и обхода существующих threads (`internal/win/proc/shield.go:175`, `internal/win/proc/conhost.go:154`). Unknown birth-console answer отказывает запуску. Три guard tests PASS; account/thread измерения — только в удалённом CI. |
| Relay | `claimClose` под mutex забирает HPCON; resize регистрируется под тем же mutex; free ждёт начатые resizes (`internal/sandbox/exec/console.go:504`, `:532`, `:806`). Четыре tests с fake HPCON и малыми pipes PASS. Это подтверждает порядок ownership, не native hang на всех версиях Windows. |
| Job/lease | Account job заканчивается перед bridge drain (`internal/win/proc/logon.go:1171`). Slot duplicate передаётся с desired access 0, без наследования (`internal/base/lock/slot.go:191`); slot защищён owner-only. Локальные crash/account e2e не запускались. |
| Accounts/profile | Проверяется принадлежность account проекту; восстановительное удаление требует creator SID оператора (`internal/sandbox/init.go:372`). MakeProfile проверяет hard links до ACL и публикует hive после tightening (`internal/account/ownprofile.go:51`, `:162`). DPAPI buffers/LSA/registry handles имеют явное освобождение на просмотренных путях. |
| ACL/grant/revoke | Canonical tree lock охватывает операцию. Unknown group и исчезновение группы при member lookup отказывают до публикации ACL; оба соответствующих tests PASS. OWNER RIGHTS cap и whitelist already-capped entries сохранены. Ошибка trustee lookup при revoke даёт narrowing, не доверенный grant. |
| Links/path identity | Частичная enumeration не считается завершённой; нормальный конец — `ERROR_HANDLE_EOF` (`internal/win/pathid/pathid.go`). Адресные tests отказа enumeration через grant и Copy PASS; файл не был перезаписан после отказа проверки. |
| SID lifetime | Форматирование использует typed adapter, backing buffers удерживаются до native чтения. Четыре tests formatter/CurrentUser/name lookup PASS. ACL identities владеют parsed SID и Go SID storage до End. |
| Check/audit | Check создаёт primary и impersonation token, освобождает их, возвращает ошибки AccessCheck. Audit читает ACE по порядку, пропускает inherit-only для самого объекта и возвращает ошибки чтения descriptor. Три ACE-order tests и один lifetime/read-count test PASS. Audit двух identities не моделирует полный token. |

Ограничения `docs/limits.md` сохраняются: общий desktop/clipboard, сеть,
доступные всем writable locations, уже открытые handles и locks только
одного оператора. Этот отчёт не расширяет документированную гарантию до
изоляции GUI, сети или всех способов доступа в Windows.

## P2-1 — alias memo превращает unknown в absence и вновь допускает потерю record

**Статус:** неполное закрытие P2-1 round12 после `c33a81e`.
**Confidence:** высокая для потери состояния в control flow; публичный
сценарий ниже выведен статически, совместный runtime test не выполнялся.

**Evidence.** `canonicalEntryPath` теперь сохраняет unknown и исходную ошибку
при неудачном alias open/canonicalization
(`internal/policy/profile/place_resolve.go:59`, `:64`, `:71`). Но при попадании
в alias memo читает **только `memo.canonical`** (`:54–55`), игнорируя unknown
и err. Для сохранённого отказа canonical пуст, поэтому выход `:194–196`
возвращает обычный `placeResult{}`. `place` затем кеширует этот ложный miss
уже под полным новым spelling (`place_resolver.go:267–273`).

Минимальный пример контракта: каталог хранится как `AppData`, alias `APPDATA`
временно не открывается. В одном resolver первый запрос
`APPDATA/first` вернёт unknown, второй `APPDATA/second` — absence через memo
того же префикса, хотя вопрос об `APPDATA` по-прежнему не получил ответа.
Это не повтор одного полного ключа: такой повтор действительно возвращает
unknown из `places`, поэтому одиночный regression не обнаруживает дефект.

Есть и второй вход: неполный sibling scan пишет в alias memo пустой result
**до** возврата unknown (`place_resolve.go:177`, `:186`). Исправить только
чтение unknown недостаточно: этот путь сначала должен сохранить сам unknown.

`placeIndex.index` записывает неизвестные spelling отдельно, однако `vouches`
считает их основанием отказа лишь при `result.unknown` либо `result.ok`.
Ложный miss проходит до `vouchAbsent` даже при непустом unknown set
(`internal/policy/profile/place_index.go:348–362`). `copyEntries` молча
пропускает такой entry (`copy.go:314–330`).

**Статический сценарий через публичный Copy и сохранение record:**

1. Destination содержит штатный `AppData` и ранее скопированный
   `APPDATA/auth.json`. Previous record в этом порядке содержит
   `APPDATA/Local/Microsoft/Windows/UsrClass.dat` и `APPDATA/auth.json`.
   Первый — известный reserved entry: такой legacy record допустим; текущий
   Copy тоже способен выдать его при прямом правиле и существующем source,
   поскольку append entry предшествует reserved skip (`copy.go:343`,
   `mirror.go:70–75`). Preflight не запрещает обычное написание hive path.
2. Теперь список правил содержит только `APPDATA/auth.json`, его source
   отсутствует, а destination `AppData` временно закрыт exclusive handle.
3. В forget известный reserved entry сохраняется без удаления, второй
   пропускается по точному spelling (`forget.go:64`, `:85–95`). Неизвестный
   ответ о первом не становится ошибкой этой стадии: reserved path известен
   по самим таблицам, его и следует оставить.
4. В новом index copyEntries первый recorded path сохраняет unknown для
   alias `APPDATA`; второй получает false absence из того же alias memo.
   `vouches("APPDATA/auth.json")` отвечает absent. Copy возвращает пустой
   copied list и nil, хотя destination-копия осталась за закрытым каталогом.
5. `fillProfile` выбирает successful union и сохраняет пустой record
   (`internal/cli/setup/run.go:158–175`, `:196–200`). После снятия hold
   последующий Clear уже не знает об `auth.json`.

**Impact.** Отказ identity снова может разрешить успешное завершение и потерю
учёта credential/config copy. Это fail-open учёта отзыва; запись за пределами
sandbox и sandbox escape этой цепочкой не установлены. Сценарий требует
нескольких recorded paths и общего alias-префикса; это не утверждение,
что простой default list всегда теряет запись.

**Recommendation.** Сохранять все три результата на каждом входе и выходе
alias memo, включая partial scan. Добавить проверку двух полных spelling
с общим недоступным alias-префиксом, затем Copy/fillProfile regression,
который не маскируется ранней ошибкой первого missing-source entry.
Проверить record до/после отказа, retry и последующий Clear. Известный
reserved hive должен по-прежнему оставаться нетронутым.

**Tests.** Новый single-entry
`TestAMissingSourceBehindALockedAncestorStopsTheCopyAndTheRecordSurvives`,
absent control и `TestAClearThatCannotResolveASuspiciousRecordStopsAndTheRetryTakesItBack`
PASS. Первый моделирует caller union внутри profile test после снятия hold;
он не вызывает реальный fillProfile. Эти результаты закрывают прежние
одиночные пути, но не описанный общий alias memo.

## P3-1 — structural refresh всё ещё повторно обходит неизменные siblings

**Статус:** CPU-часть прежнего P3-1 открыта; прежний механизм квадратичных
canonical-map allocations закрыт. **Confidence:** высокая для асимптотики
по control flow; время, GC pauses и полные allocations/op не измерены.

**Что исправлено.** `childAt` и swap-with-last устраняют фильтр children
при каждом удалении (`place_resolver.go:115`). `removeSnapshotChild`
возвращается сразу для отсутствующего имени (`place_index.go:118`).
Canonical membership maps дополняются по новым ответам, completeness теперь
сохраняется в `r.dirs` (`place_resolve.go:149–172`). Эти изменения действительно
устраняют две прежние причины лишней работы и stale completeness.

**Оставшийся механизм.** `placeIndex.refresh` вызывается после mirror, но
спрашивает `resolver.place(path)` **до** обновления snapshot
(`place_index.go:265`, `:289`). После предыдущего создания generation родителя
увеличена, поэтому старый miss очередного имени уже не подходит
(`place_resolver.go:254`). Файл теперь существует на диске, а `byName` и
`byCanonical` snapshot ещё не содержат этого нового имени. Alias branch
открывает его и снова проходит весь `snap.children`
(`place_resolve.go:59–94`). Проверка `snap.canonical[name]` внутри цикла
устраняет повторное native resolution, **но не посещение самого child**.

Возьмём имеющийся structural fixture: B неизменных root-level файлов и M
других имён, которые зеркала последовательно создают вновь. Первое создание
читает ещё валидный miss; последующие M−1 уже требуют описанного scan.
`refreshSnapshots` добавляет новые имена в maps, не расширяя исходный slice
children (`place_index.go:91–103`). Получается как минимум **(M−1)·B**
посещений прежних children; при B=M=E/2 это **Ω(E²)** CPU-работы.
Эта оценка выведена из кода, не из timing benchmark.

**Impact.** Большой пользовательский список всё ещё может дорого обновляться
при множественных creations. Нельзя объявлять весь structural refresh
линейным. При этом теперь нельзя переносить старый вывод `Ω(MB+M²)` на
число заново создаваемых canonical membership maps: известные rows больше
не пересоздаются при каждом scan. Cumulative allocations и одновременно
удерживаемая память — разные величины.

**Recommendation.** Не резолвить уже созданное имя через ещё не обновлённый
snapshot только для определения его прежнего родителя/dependency. Передавать
или сохранять нужную информацию о mutation и обновлять затронутые ответы
адресно, сохранив alias/unknown semantics. Считать все cached-child visits,
включая проходы, которые только проверяют уже известный canonical key.

**Tests.** Mixed warm, structural E=4/8, partial clear, nested creation и
completeness tests PASS. Structural test проверяет `canonicalMaps == E`,
но разрешает до E/2 scans (`place_alias_test.go:394–397`). Counter `children`
считает обработку ReadDir, а не итерации alias scans; `visits` считает
retraction books. Поэтому нынешние PASS совместимы с указанной квадратичной
суммой. Старое квадратичное фильтрование siblings при partial clear закрыто.

## P3-2 — allocation assertion измеряет memo hit вместо первого запроса после refresh

**Статус:** новая погрешность доказательства в `3032a34`.
**Confidence:** высокая; сверены код test и локальный `go doc testing.AllocsPerRun`.

**Evidence.** В `internal/policy/profile/place_refresh_test.go:87` вызов
`testing.AllocsPerRun(1, func() { probe = resolver.place("Q7X") })` использует
один уже подготовленный resolver. AllocsPerRun сначала исполняет closure
один раз вне измерения. Этот warm-up заполняет memo для Q7X; измеряемый вызов
получает готовый answer из `places`. Контроль `freshAllocs` создаёт resolver
внутри closure (`:130–132`) и потому действительно платит за первый запрос.

**Impact.** Сравнение `probeAllocs < freshAllocs/2` не доказывает заявленную
стоимость первого нового spelling после refresh. Дорогой первый запрос
попадает в исключённый warm-up. Это не опровергает scan/map counters:
они сняты до обоих вызовов и проверены после них, поэтому обнаруживают
свои структурные регрессии.

**Recommendation.** Измерять сопоставимые начальные состояния: каждый
учитываемый вызов должен впервые спрашивать spelling у отдельно подготовленного
resolver. Разделить стоимость подготовки и стоимость самого запроса;
сохранить независимые проверки результата и scan/map counters.

**Tests.** Сам test PASS в этом ревью. Численного результата для первого
запроса из его текущего allocation assertion извлечь нельзя. Production
allocation regression этой находкой отдельно не заявляется.

## Состояние остальных выводов round12 и relay CI

| Вывод round12 | Состояние на HEAD |
| --- | --- |
| Missing source + inaccessible destination | Single-entry путь закрыт трёхзначными snapshot/place/vouches; regression и retry/Clear PASS. Multi-entry alias-memo пробел описан в P2-1. |
| Clear над unknown legacy alias | `reservedUnknown` теперь возвращает ошибку; известный reserved объект остаётся spared. Адресный locked-file test и 13 hive-alias subtests PASS. |
| Plan refusal без destination | Сохранён refusal перед nil-root return; оба соответствующих Plan tests PASS. |
| Nested prepareDir, unrelated basename | Оба public Copy fixtures PASS. Нынешний тест nested creation не является полной проверкой равенства всех ответов жившего index со свежим после каждой mutation. |
| Partial exclusions и terminal-leaf retraction | Оба fixtures PASS; `retract` доходит до terminal leaf, holding directory не теряется при сохранённом excluded child. |
| Quadratic refresh | Child removal, map rebuilding и completeness исправлены; repeated cached-child scans остаются, P3-1. |
| Inconsistent relay CI | Для текущего SHA проверен один завершённый успешный run; прежние противоположные verdicts относятся к `33dd8f4`. |

Отмеченный round12 предел legacy misses тоже сохраняется: trie индексирует
компоненты через `foldedName` (`place_index.go:182–208`), поэтому прежний miss
`file.` не находится через `under("file")` после создания `file`.
Generation invalidation сама не дополняет membership. Новый публичный
сценарий потери record именно из-за этого варианта не выполнялся; отдельная
P2 о его последствиях здесь не заявляется.

В `3c9116c` устранён конкретный пробел live-close oracle: writer закрывает
`blocked` только после исчерпания prefix, и test ждёт его до finish
(`internal/sandbox/exec/console_test.go:1368`, `:1622`). Фиксированная пауза
200 ms больше не служит доказательством stall. Exit code теперь сохраняется
в `childRun`. Resize readiness читает измеренный child `widthxheight`, а
deadline увеличен с 20 до 30 s. Это улучшает gate и диагностику, но не
устанавливает историческую причину отсутствовавшего ready-file.

Проверен [run 35912318456](https://github.com/PHPCraftdream/wuserbox/actions/runs/35912318456),
attempt 1, event push, точный SHA `fa5abf7034279d65bb5689d8ad8eed199be98e28`.
[Job 107355008600](https://github.com/PHPCraftdream/wuserbox/actions/runs/35912318456/job/107355008600)
завершился success **19:58:23 UTC**: formatting, vet, lint, Test, Delete
boundary, Registry hive picture и Own console measurement прошли.
В boundary log — **80 фактических top-level PASS**, без фактических SKIP;
есть PASS для conhost/thread/birth-host, hive и own-console measurements.
Runner использовал **Go 1.26.8 windows/amd64**, локально был 1.26.0.

В общем Test step `internal/sandbox/exec` завершился `ok` за 14.556 s,
без `(cached)`. Этот шаг не печатает успешные tests поимённо и не является
отдельным повторным прогоном двух прежних live failures. Старый
[failed run 35875827665](https://github.com/PHPCraftdream/wuserbox/actions/runs/35875827665)
из round12 не считается падением нового SHA. Механизм stall oracle исправлен,
новое выполнение CI успешно; независимого доказательства отсутствия всех
relay flakes, `-race` результата или native-hang measurement на нескольких
поколениях Windows этот раунд не даёт. Локально live tests не запускались.

## Сложность, проходы и память

E — entries, S — сумма компонентов путей, B — дети прочитанных каталогов,
M — mutations, N — объекты дерева, A — ACE объекта, T — ожидаемые ACE,
G — identities, H — hard-link names, d — глубина, L — переносимые байты.
Оценки для maps предполагают обычную среднюю стоимость lookup.

| Участок | Работа, проходы и allocations |
| --- | --- |
| Profile resolver | Build зависит от S+B и alias resolutions; exact cached lookup — map lookup. Maps/trie/reverse books живут одну операцию. `childAt` добавляет O(B) Go storage в обмен на O(1) removal. `ReadDir(-1)` держит список целиком; уменьшение slice не гарантирует освобождения его backing array до конца операции. Structural cached-child work — P3-1. |
| Profile Copy/Plan | Cleanup, forget, source traversal, destination reconciliation и итоговый Dedupe — отдельные проходы. Нельзя называть весь Copy одним обходом. Стриминг O(L), один lazy 32 KiB scratch на Copy; проверяются рост source и изменение размера/mtime к концу. 64 MiB ceiling не ограничивает число пустых файлов и metadata/maps. |
| Paths/hard links | Canonical начинает с 256 UTF-16 slots; буфер растёт по ответу. Names перебирает H имён, Within делает ancestor identity checks порядка H·d. `root.Open` и последующий Canonical открывают объекты отдельно; resolver opens-counter не является счётчиком всех Windows opens. |
| Grant sweep | Preflight и narrowing — два обхода; classification читает descriptor, writer перечитывает его у изменяемого объекта, root публикуется отдельно. До 8 workers, ordered window до 16; preflight queue — 128. Это границы очередей, не всей памяти WalkDir/pinned snapshots. ACE work зависит от A и G; `alreadyCapped` допускает O(A·T). |
| Revoke | Один основной WalkDir плюс optional pinned preparation. Операционные identities и trustee memo устраняют повторные name lookups одного SID; CopySid остаётся на eligible lookup. Memo хранит один 68-byte scratch и ключи distinct SID. Аллокационный test сравнивает hit с shared-scratch baseline; native heap bytes он не считает. |
| Grant/state | Canonical keys кешируются на срок index. Save, построение списка pinned paths, вложенные grants и сброс index при изменениях остаются отдельными затратами. Серия изменений E grants не становится автоматически O(E). |
| Startup/Shield | Logon/token/job/pipe handles имеют ограниченное число владельцев на запуск, но Toolhelp перечисляет системные процессы/threads. Birth-host/thread retries повторяют такие перечисления; постоянная стоимость запуска независимо от размера системных списков не доказана. |
| Relay | Production переносит потоки через io.Copy, не накапливая весь вывод в собственном buffer. Drain ceiling ограничивает ожидание stub, а не длительность native close/goroutine. Process termination остаётся конечной границей освобождения при таком зависании. |
| Check/audit | Audit парсит два SID на pass, читает один descriptor на объект и проходит ACE по порядку. Check держит primary/impersonation tokens на Asking; AccessCheck выделяет Go privilege buffer на вопрос, при delete может дополнительно читать parent. |
| Native vs Go | SID/ACL/security-descriptor/NetAPI allocations освобождаются владельцами на просмотренных обычных путях; handles закрываются через defer/ownership. Go escape diagnostics подтверждают heap maps и scratch, но не измеряют число/байты native allocations. Native heap profile и длительный handle-count experiment не проводились; абсолютное отсутствие утечек не заявляется. |

Compiler diagnostics на HEAD показывают heap escape `childAt` и остальных
snapshot maps (`place_resolver.go:349–363`), новых canonical membership maps
(`place_resolve.go:149`, `place_index.go:96`) и scratch
(`mirror_file.go:29`). Escape сам по себе не означает регрессию, а эти строки
не определяют число выполнений allocation site. Для P3-1 принципиально,
что дорогой повторный проход теперь может не создавать ни одной новой
canonical membership map.

## Выполненные проверки

Runtime tests запускались только по явным полным именам, с
`-count=1 -p=1 -parallel=1 -timeout=60s -v`. Subtests отдельно в 49 не включены.

| Проверка | Результат |
| --- | --- |
| `internal/policy/profile`: три unknown/absent/alias-Clear controls; mixed warm/structural; miss create/delete; partial scan; mutation parent и nested creation; partial/excluded/terminal retraction; retention/never-copied controls; preflight; nil-destination Plan; locked cleanup; hive aliases; bounded copy/scratch | 25 top-level PASS. |
| `internal/sandbox/exec`: три birth-host guards, resize-before-close, hung fake close ceiling, drain-first close ownership, deferred pipe-only cleanup | 7 PASS; реальный ConPTY не создавался. |
| `internal/win/sid`: failed formatter, CurrentUser propagation, manually built SID bytes, failed name lookup reason | 4 PASS. |
| `internal/win/pathid`: partial enumeration, отказ grant/Copy, Canonical growth/ceiling, file-root external hard link | 6 PASS. |
| `internal/win/acl`: два unknown-group guards, три ACE-order cases, audit descriptor/SID lifetime, trustee memo allocation control | 7 PASS. |
| `go vet -p=1 ./internal/policy/profile ./internal/sandbox/exec` | PASS. |
| `go test ./internal/policy/profile -run '^$' -p=1 -gcflags='-m'` | PASS, compile/escape diagnostics, без дополнительных runtime tests. |
| `gofmt -l` по 18 изменённым после round12 Go-файлам | Пустой вывод. |
| `git diff --check 33dd8f4..HEAD` | PASS. |

Пробелы: нет нового multi-entry runtime regression P2-1, измерения всех
cached-child visits, полного allocation profile Copy, локальных account/hive/
lease-crash e2e, live ConPTY, `-race` и ARM64 runtime. Удалённый CI не включён
в число локальных PASS. Существующие tests не менялись ради получения verdict.

## Release verdict

**NO-GO до закрытия P2-1:** перед сохранением successful record unknown
не должен превращаться в absence при повторном alias-префиксе. Нужен
регрессионный результат именно для нескольких entries и сохраняемого record,
после чего — проверка итогового кода. P3-1/P3-2 сами по себе не блокируют
небольшой default list, но исключают заявление о доказанной линейности
structural refresh и измеренной стоимости первого запроса после mutation.

Новый зелёный CI — положительное evidence для проверенного SHA, а не причина
игнорировать непокрытую ветку. Tag release по-прежнему независим от tests
workflow (`.github/workflows/release.yml:3`); GoReleaser запускает общий
`go test ./...`, но не требует специальных no-SKIP/own-console gates
(`.github/goreleaser.yaml:7`). ARM64 собирается, но runtime evidence здесь
только amd64; npm явно поставляет amd64 для эмуляции на ARM64. Версия parser
DLL совпадает с go.mod, отдельный ожидаемый digest при скачивании не проверяется.

Исправления не внесены по условию пользователя. Единственный сохраняемый
результат — этот отчёт, менее 500 строк; частных локальных путей в нём нет.
