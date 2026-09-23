# Security and performance review — round 12 — P0–P3

## Вердикт и проверенный срез

**P0 — 0; P1 — 0; P2 — 2; P3 — 1. Выпуск пока не рекомендован.**
Подтверждённого нового sandbox escape не найдено. Потеря profile record при
неизвестном состоянии destination из round11 остаётся. На текущем SHA есть
как успешный CI со всеми boundary gates, так и отдельный неуспешный CI с двумя
падениями live-relay tests. Квадратичная работа и поток allocations при
structural refresh также сохраняются.

Проверен чистый **`33dd8f405feca2ab675ee84c472a4d5ca454dec0`** в отдельном
worktree. Последние семь календарных дней относительно HEAD — **17–23 сентября
2026 включительно**, 224 коммита, 201 без merge. Даты 29/30 сентября в именах
round9/10/11 не являются датами будущих коммитов. В отличие от тех ревью,
profile patch этого раунда полностью входит в указанный SHA.

Прослежены account → stub → restricted token, ConPTY/conhost/Shield/threads,
relay/jobs/lease, ACL/grant/revoke/hard links/path identity, profile
copy/cleanup/Plan, check/audit и CI/release. История недели использовалась для
выделения изменившихся инвариантов; каждый промежуточный SHA отдельно не
собирался. Основные участки истории:

| Период | Изменения, проверенные на итоговом коде |
| --- | --- |
| 17–18 сентября | OWNER RIGHTS, hive inheritance, account ACE, Unicode/path identity, hard-link preflight, параллельный ACL sweep. |
| 19–20 сентября | Отказы identity/exit-code, streams, owner-only slot, console relay, job-before-drain, reserved-name resolution. |
| 21–22 сентября | Conhost/thread shield, relay close ownership, SID lifetime/typed adapter, bounded copy/scratch, lookup failures, revoke memo, audit ACE order, warm/partial resolver. |
| 23 сентября | Reserved ancestor aliases, Copy preflight, excluded-child/terminal-leaf retraction; `33dd8f4` — Plan refusal, incremental index, prepareDir ancestor chain и разделение файлов. |

Локально использовался Go **1.26.0 windows/amd64**. Выполнены 53 адресных
top-level tests: **53 PASS, 0 FAIL, 0 SKIP**. Fixtures маленькие и временные;
UAC, реальные sandbox accounts, видимые окна, пользовательские профили,
нагрузочные прогоны и benchmarks не использовались. Production-код, тесты,
workflow, зависимости и версии не изменялись; единственный сохраняемый
артефакт — этот отчёт.

## P0 — подтверждённых находок нет

`setup.Run` отказывает account-less запуску и берёт slot до `fillProfile`
(`internal/cli/setup/run.go:51`, `:72`, `:78`). В account launch stub создаётся
suspended, получает job, lease и закрытый process DACL до resume
(`internal/win/proc/logon.go:1084`, `:1128`, `:1133`, `:1154`). Затем stub
проверяет birth conhost, строит restricted token, подготавливает консоль и
проходит Shield до исполнения команды (`internal/sandbox/exec/stub.go:165`,
`:168`, `:185`, `:222`, `:254`). Restricted child тоже входит в job до resume
(`internal/win/proc/run.go:232`).

В `internal/win/token/restricted.go:133` сохранены `DISABLE_MAX_PRIVILEGE`,
restricting SID list и lifetime user/logon/read-group buffers. Собственная
identity здесь принадлежит sandbox account. Обе проверки доступа должны
разрешить операцию — именно так Windows определяет
[restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens).
Нового пути запуска пользовательской команды под unrestricted token в
просмотренной цепочке нет. Это не утверждение о полной изоляции Windows.

## P1 — подтверждённых находок нет

| Участок | Evidence и предел вывода |
| --- | --- |
| Shield/conhost/thread/token | Default DACL для будущих threads закрывается до process и уже существующих threads (`internal/win/proc/conhost.go:146`, `internal/win/proc/shield.go:175`). Unknown birth-console answer возвращает ошибку (`internal/sandbox/exec/console.go:180`); три адресных guard tests PASS. Реальные account/thread probes локально не запускались. |
| Relay | `claimClose` синхронно забирает HPCON под mutex; resize регистрируется под тем же mutex; free ждёт начатые resizes (`internal/sandbox/exec/console.go:504`, `:528`, `:796`). Четыре tests с подменённым native call подтвердили порядок, ceiling и одного владельца close. Это не измерение live ConPTY; его CI отдельно разобран в P2-2. |
| Job/lease | Job закрывается до обычного bridge drain (`internal/win/proc/logon.go:1171`). Slot передаётся с нулевым desired access и без наследования (`internal/base/lock/slot.go:191`); handoff защищён, slot owner-only (`:127`, `:372`). Crash/lease e2e локально не исполнялись. |
| ACL/grant/revoke | Canonical tree lock охватывает изменение (`internal/policy/grant/apply.go:44`, `revoke.go:23`). Unknown group и исчезновение группы между SID/member lookup останавливают операцию (`internal/win/acl/owner.go:319`); оба соответствующих Isolate tests PASS. OWNER RIGHTS cap и строгий whitelist уже capped ACL сохранены (`owner.go:554`, `reclaim.go:97`). |
| Native lifetime | `sid.CurrentUser` передаёт pointer типизированным до конкретного native adapter и удерживает backing buffer (`internal/win/sid/current.go:54`, `sid.go:43`). ACL descriptors освобождаются после чтения owner/ACE; identities владеют parsed SID и Go SID storage до `End`. Нового аналога прежнего unsafe interface adapter не найдено. |
| Links/path identity | Частичная enumeration не считается полной: успешный конец только `ERROR_HANDLE_EOF` (`internal/win/pathid/pathid.go:223`). Проверки external hard links/reparse destination предшествуют truncation (`internal/policy/profile/mirror_file.go:105`, `:128`). Адресные отказные tests через grant и Copy PASS. |
| Account/profile initialization | Замена unopenable account требует creator SID оператора (`internal/sandbox/init.go:372`). MakeProfile проверяет links перед ACL, создаёт подкаталоги через `os.Root` и публикует hive после tightening (`internal/account/ownprofile.go:51`, `:114`, `:162`). Registry/account mutations локально не выполнялись. |
| Check/audit | Check использует sandbox token и impersonation copy, ошибки AccessCheck возвращаются наружу (`internal/win/access/check.go:85`, `:219`). Audit читает один descriptor на объект, учитывает порядок ACE и пропускает inherit-only для самого объекта (`internal/win/acl/entries.go:297`, `:413`); четыре адресных tests PASS. Audit двух identities не заменяет проверку полного токена. |

Shared desktop/clipboard, сеть, общедоступные writable locations, ранее
открытые handles и отсутствие межоператорных locks остаются ограничениями
`docs/limits.md`. Windows отдельно рекомендует другой desktop для restricted
applications; одного token restriction недостаточно для GUI isolation
([Microsoft](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens)).
Успех проверки файловой границы эти ограничения не отменяет.

## P2-1 — неизвестное состояние копии всё ещё разрешает забыть её record

**Статус:** открытый P2-1 round11; в `33dd8f4` не исправлен. Дополнительно
прослежен соседний unknown-alias путь через Clear. **Confidence:** высокая
для control flow и последствий сохранения record. Совместный новый runtime
probe не создавался и не выполнялся.

**Evidence.** `snapshot` переводит любую ошибку `root.Open`/`ReadDir` в
`dirSnapshot{}, false`, не сохраняя причину (`place_resolver.go:259–276`).
`canonicalEntryPath` возвращает false, `index` не создаёт membership, `holds`
отвечает false (`place_resolve.go:31–34`, `place_index.go:228–239`, `:299–304`;
все три файла — `internal/policy/profile`).

В `copyEntries` любой отказ `os.Stat(source)` идёт в ветку missing source;
entry сохраняется только при `stretch.holds(entry.Path)==true`, а false не
создаёт ошибку (`internal/policy/profile/copy.go:294–317`, `:346`).
Смена способа обновления index эту семантику не изменила.

Цепочка через публичный Copy:

1. Ранее скопирован и записан `agent/auth.json`; правило сохраняет то же имя.
2. Source отсутствует, а каталог destination `agent` временно недоступен,
   например удерживается exclusive directory handle без sharing.
3. `forget` пропускает совпавшее написание (`internal/policy/profile/forget.go:42–65`).
4. Index не может открыть `agent`, membership остаётся пустым. Copy возвращает
   пустой copied list и `nil`, хотя destination-файл остался.
5. `fillProfile` выбирает successful union и сохраняет только новый list
   (`internal/cli/setup/run.go:158–175`, `:196–200`). Старый entry исчезает.
6. После снятия lock дальнейшие Clear/`--no-ai` уже не знают о копии.

**Соседний путь того же дефекта.** Для прежнего suspicious spelling, например
`auth.json.`, unknown resolution возвращается как `true` из
`reservedAtResolved` (`internal/policy/profile/reserved.go:240–254`, `:304–306`).
`forget` воспринимает его как известный reserved объект и просто продолжает
(`forget.go:80–82`). Clear может успешно завершиться над оставшейся обычной
копией; `fillProfile` с `NoAI` затем сохраняет пустой record (`run.go:147–156`).
Здесь missing source вообще не требуется. Спасти неизвестный объект от
удаления правильно; сообщать, что take-back завершён, и терять возможность
retry — другая, неверная часть решения. Это статически прослеженный вариант,
не новое runtime воспроизведение и не отдельный sandbox escape.

**Impact.** Временный отказ destination превращается в постоянную потерю
учёта credential/config copy. Операция сообщает успех, последующий отзыв
копии её не достигает. Это fail-open учёта и отзыва скопированных данных;
запись за пределами sandbox этой цепочкой не доказана.

**Recommendation.** Донести различие absent / resolved / unknown до решения
о сохранении previous record. Unknown, влияющий на retention или take-back,
должен сохранить запись и возможность retry; существующий partial-record
механизм уже делает это при ошибке Copy. Для Clear нельзя смешивать известный
reserved hive и объект, чью identity проверить не удалось. Не присваивать
никогда не копировавшиеся sandbox-owned файлы и не удалять по одному fold.

**Tests.** Существующие missing-source retention, respelling, never-copied
control и locked-destination/locked-cleanup tests PASS по отдельности.
Их сочетание не покрыто. Нужен regression через `fillProfile`: previously
recorded nested file + missing source + locked ancestor; проверить ошибку,
сохранённый record, retry и Clear. Отдельно проверить ordinary legacy alias
с unknown resolution через `NoAI`, а известный reserved hive оставить
нетронутым. Новые тестовые файлы по условию ревью не добавлялись.

## P2-2 — CI текущего SHA нестабилен; live-relay test не доказывает свой stall

**Статус:** новое наблюдение этого раунда о текущем CI. **Confidence:** высокая
для фактических падений и дефекта синхронизации fixture; причина задержки
первого PowerShell child не установлена. Production escape/hang по этим
логам не доказан.

**Evidence.** GitHub API и job logs проверены для одного и того же
`33dd8f405feca2ab675ee84c472a4d5ca454dec0`:

| Run | Фактический результат |
| --- | --- |
| [35875827877](https://github.com/PHPCraftdream/wuserbox/actions/runs/35875827877) | Success; Test, Delete boundary, Registry hive picture и Own console measurement прошли. В логах есть PASS именованных conhost/hive/own-console probes. |
| [35875827665](https://github.com/PHPCraftdream/wuserbox/actions/runs/35875827665/job/107231346567) | Failure в Test; три последующих boundary/hive/own-console steps skipped. `TestAResizeMessageReshapesTheRelayedConsole` упал за 21.27 s, `TestALiveConsolesHungCloseIsStillBoundedByTheCeiling` — за 22.03 s. |

Оба runs созданы `2026-09-23T14:39:48Z`, event `push`, attempt 1.
В resize test не появился ready-file; capture содержит только начальные
terminal control sequences. Это ошибка readiness, до проверки результата
resize (`internal/sandbox/exec/console_test.go:519–527`). Точную причину
медленного/остановившегося child этот лог не объясняет.

В live-close test verdict `finish` оказался `nil`, хотя assertion требует
`incomplete` (`console_test.go:1450–1456`). Fixture дожидается ready-file,
который child пишет **до** вывода, затем ждёт фиксированные 200 ms и вызывает
finish (`:1395`, `:1410–1437`). У `prefixBarrierWriter.Write` нет сигнала
«достигнут лимит prefix, writer действительно заблокирован» (`:1249–1269`).
Поэтому после ready остаётся допустимое расписание: нужный объём вывода ещё
не дошёл до barrier, close завершает клиента, drain получает EOF, finish
законно возвращает nil. Ready-file и 200 ms не устанавливают предусловие
assertion. Из лога нельзя утверждать, что именно это расписание было
единственной причиной, но сам пробел в oracle следует из кода.

Дополнительно fixture выбрасывает числовой child exit code (`:1407–1408`),
поэтому диагностическое `child's exit: <nil>` сообщает только об отсутствии
ошибки запуска/ожидания, а не об успешном завершении child.

**Impact.** Одинаковый SHA получает противоположные CI verdicts; один запуск
не доходит до security gates. Нельзя засчитывать случайный успешный повтор
как устранение причины. Это P2 надёжности проверки/release, не P1 native
close regression.

**Recommendation.** Сигнализировать вход в blocking Write и ждать этого
сигнала перед finish. Для resize измерять readiness управляемого child,
сохранять его `(exit code, error)` и собирать диагностические данные при
превышении deadline. На всех error paths завершать принадлежащие fixture
goroutines/handles до восстановления глобальных hooks. Повторить ровно эти
два tests в CI после исправления механизма, затем обязательные gates.

**Tests.** Локально выполнены семь guard/relay tests без реального ConPTY;
все PASS. Два упавших live tests локально не запускались: один намеренно
генерирует тысячи строк и resizes, что выходит за ограничения этого ревью.
Workflow и fixtures оставлены без изменений по прямому условию «исправления
не делай». Ограничения native close зависят от поколения Windows: до 24H2
возможен блокирующий close, на новых сборках важен EOF output pipe
([Microsoft](https://learn.microsoft.com/en-us/windows/console/closepseudoconsole)).

## P3-1 — structural refresh и partial clear сохраняют квадратичную работу

**Статус:** P3 round10/11 остаётся открытым; commit message `33dd8f4` прямо
оставляет neighbor-list cost неисправленным. **Confidence:** высокая для
асимптотики и heap escape; wall-clock/GC паузы и native heap не измерялись.

**Evidence, CPU.** `refreshSnapshots` дважды вызывает `removeSnapshotChild`
для каждого компонента; оба вызова проходят `children` через `withoutChild`,
даже когда имени нет (`internal/policy/profile/place_index.go:91–123`). При
`B` постоянных соседях и `M` новых root-level именах это минимум `2·M·B`
посещений. При `B=M=E/2` получаем `Ω(E²)`. Partial take-back тоже фильтрует
slice при каждом удалении (`place_retract.go:134`): удаление половины
siblings оставляет квадратичную сумму посещений, хотя reverse books уже
устранили полные обходы всех resolver maps.

**Evidence, Go allocations.** После смены generation `refresh` повторно
спрашивает старый miss (`place_index.go:249`). Alias scan затем очищает
`canonicalNames` и создаёт новые внутренние maps для всех известных
canonical names (`place_resolve.go:76–123`). На последовательных creations
с неизменными соседями получается `Σ(B+j)`, то есть `Ω(MB+M²)` cumulative
allocation work. `go test -run '^$' -gcflags='-m'` на этом SHA подтверждает
`place_resolve.go:115: make(map[string]bool) escapes to heap`.

`snapshot` возвращает struct по значению (`place_resolver.go:259–261`),
а `snap.canonicalComplete = complete` не записывается обратно в `r.dirs`
(`place_resolve.go:96`). Maps общие, этот bool — нет. `rebuildCanonical`
видит старый false и удаляет unique fast-path answer (`place_index.go:133`).
Это оставляет дополнительные alias scans после mutation.

**Impact.** Число ReadDir и resolutions улучшено, но CPU/GC стоимость больших
списков остаётся квадратичной. Cumulative allocations не означают
квадратичную одновременно удерживаемую память. Для небольшого default list
это само по себе не security blocker.

**Recommendation.** Обновлять child set/canonical membership адресно,
устранить безусловные фильтрации отсутствующего имени и пересоздание всех
внутренних maps; хранить completeness в сохранённом snapshot. Измерять все
cached-child visits и allocation work вместе с native resolution opens.
Сохранять unknown/alias semantics и сравнивать incremental ответы со свежим
index после каждой mutation.

**Tests.** Mixed structural, mixed warm, warm-copy и partial-clear tests PASS
на существующих маленьких fixtures. Structural test при E=4/8 проверяет
один resolver, один ReadDir, `children=E/2`, `resolutions=2E−1` и допускает
до E/2 scans (`place_alias_test.go:356`). Он не считает `withoutChild`
visits, canonical-map rebuilds и все Windows opens. Полного allocations/op
для Copy и performance benchmark в этом раунде нет.

## Закрытые регрессии и оставшиеся пределы проверки

| Предыдущий вывод | Состояние на HEAD |
| --- | --- |
| Round9: Plan с reserved cleanup при отсутствующей destination | Закрыт: refusal перед nil-root return (`cleanup.go:50–59`); четыре соответствующих tests PASS. |
| Round10: prepareDir с несколькими отсутствующими предками | Закрыт конкретный wrong-parent путь: `mirror.go:192–210` сообщает верхнего созданного предка, `place_index.go:245–273` разделяет parent и miss dependency. Public Copy с nested directory и locked unrelated basename PASS; прежний file-entry fixture тоже PASS. |
| Round11: missing-source + locked-destination retention | Не закрыт; P2-1 выше. Наличие нового incremental index не даёт ошибки, которой нет в lookup contract. |
| Round8: aliases/UsrClass.dat, Copy preflight, excluded-child и terminal-leaf retraction | 13 alias subtests, оба preflight tests, excluded-child fixture и terminal-leaf test PASS. Нового удаления hive в этих сценариях не наблюдалось. |
| Formatting и размер 16 файлов profile patch | `gofmt -l` пуст; максимум 488 строк. Прежнее замечание round11 о завершающих пустых строках закрыто. |

Новый `TestAMultiComponentDirectoryCreationRefreshesItsWholeCreatedChain`
проверяет правильность публичного Copy, но его заключительная «certificate»
строит **только свежий** index (`internal/policy/profile/place_copy_test.go:448–452`).
Он не сравнивает его с жившим внутри Copy index. Полную эквивалентность
incremental/fresh этим assertion утверждать нельзя.

Сохраняется отмеченный round10/11 пробел legacy miss aliases: trie хранит
записанные компоненты через uppercase (`place_index.go:167–195`). Прежний
miss `file.` не находится через `under("file")` после создания `file`;
аналогично `parent./file` после создания `parent`. Invalidation generation
не заполняет `members` самостоятельно. Это статически подтверждённый предел
refresh; публичный Copy с потерей record именно из-за этого варианта здесь
не воспроизведён и отдельной P2 о его последствиях не заявляется.

## Остальная сложность и память

Обозначения: E — entries, S — суммарное число компонентов их путей,
B — дети прочитанных каталогов, N — объекты обхода, A — ACE одного объекта,
H — hard-link names, d — глубина, L — скопированные байты.

| Операция | Оценка и ownership |
| --- | --- |
| Immutable profile resolver | Exact lookup после build — map lookup; initial work зависит от S+B, alias queries добавляют opens/scans. Partial canonical scans могут снова посещать B соседей. Operation-local maps/trie/reverse books требуют памяти по числу записей, компонентов, alias queries и snapshots; `ReadDir(-1)` хранит каталог целиком. |
| Profile stream | `O(L)` перенос байтов и один lazy 32 KiB scratch на Copy (`mirror_file.go:139`, `:182`). Проверяется рост source после измерения и изменение к концу переноса. 64 MiB byte ceiling не ограничивает количество пустых файлов, metadata, snapshots и maps. |
| Path identity | 256 UTF-16 slots с контролируемым ростом (`pathid.go:78`, `:93`, `:223`). OutsideNames требует enumeration H имён и ancestor identity checks порядка H·d. Resolution через `root.Open` и `Canonical(file.Name())` добавляет отдельные Windows opens; resolver reads-counter их не измеряет. |
| ACL sweep | Classification workers ≤8, ordered dispatch window ≤16 (`sweep.go:92`, `:123`, `:439`). Это bound очереди, не всей памяти: WalkDir и pinned snapshots имеют свою стоимость. Обработка ACE примерно линейна по A при фиксированных identity/hand списках; `alreadyCapped` содержит попарные сравнения и может стоить `O(A·T)` для T ожидаемых entries (`owner.go:554`). Нельзя объявлять весь sweep безусловно O(N). |
| Revoke memo | Один `[68]byte` scratch и map по SID bytes на операцию (`reclaim.go:290`, `:321`). Name lookup — один раз на distinct SID; `CopySid` остаётся на eligible lookup. Allocation test PASS сравнивает hit со shared-scratch baseline; название теста не доказывает нулевых затрат всей операции или native heap. |
| Grant record | `state/index.go` убирает pairwise canonicalization, ключ разрешается один раз на operation-local index. Сериализация record, построение `s.paths()`, pinned relevance и вложенные grants остаются отдельными затратами; массовые изменения не становятся автоматически O(E). |
| Audit/check | Audit: два parsed SID на pass, один descriptor на объект, линейный обход ACE; SID и descriptor возвращаются владельцем. Check держит primary/impersonation token на Asking и освобождает их; privilege buffer выделяется на access check. |
| Native vs Go | SID parses/descriptors/ACLs/handles имеют явные free/close на просмотренных success/error paths. Go maps и 32 KiB scratch подтверждены escape diagnostics. Heap profile, native heap bytes и handle-count stress не выполнялись; числовое заявление об отсутствии всех native leaks было бы сильнее имеющихся данных. |

## Выполненные проверки

Все локальные tests запускались по явным именам с
`-count=1 -p=1 -parallel=1 -timeout=60s -v`; subtests отдельно в 53 не включены.

| Пакет/проверка | Результат |
| --- | --- |
| `internal/policy/profile`: Plan nil destination, nested prepareDir, incremental create/delete, warm/structural/partial runs, alias partial scan, retention controls, locked refusal, preflight, hive aliases, links, budget/scratch | 28 top-level PASS. |
| `internal/win/sid`: formatter refusal, CurrentUser propagation, typed bytes, failed name lookup reason | 4 PASS. |
| `internal/win/pathid`: partial enumeration и отказ вызывающих grant/Copy, buffer growth/ceiling, file-root hard links | 6 PASS. |
| `internal/win/acl`: unknown group/member, ACE order, audit read/lifetime, memo allocations, drive/UNC generation arithmetic | 8 PASS. |
| `internal/sandbox/exec`: три birth-host guard tests, resize/close ordering, hung-close ceiling, drain-first ownership, deferred pipe-only cleanup | 7 PASS, только fake-HPCON seams и маленькие pipes. |
| `go vet ./internal/policy/profile` | PASS. |
| `go test ./internal/policy/profile -run '^$' -p=1 -gcflags='-m'` | PASS; compile/escape diagnostics, без дополнительных runtime tests. |
| `gofmt -l` 16 profile-файлов последнего коммита | Пустой вывод. |
| `git diff --check` | PASS. |

Совместный P2-1 probe, account/registry/lease-crash e2e, live ConPTY,
`-race`, ARM64 runtime и широкий project suite локально не запускались.
Удалённый CI не смешивается с локальными 53 PASS.

## CI/release verdict

Успешный [run на проверенном SHA](https://github.com/PHPCraftdream/wuserbox/actions/runs/35875827877)
действительно покрывает formatting/vet/lint, общий Test, 80 именованных
boundary tests и отдельные hive/own-console gates. Это уже evidence для
текущего кода, а не только для базы round11. Одновременно существует
[неуспешный run того же SHA](https://github.com/PHPCraftdream/wuserbox/actions/runs/35875827665/job/107231346567),
разобранный в P2-2; его нельзя опустить из решения о выпуске.

Tag release независим от tests workflow (`.github/workflows/release.yml:3`).
GoReleaser hook запускает общий `go test ./...`, но не ожидает специальные
no-SKIP gates и не включает own-console opt-in (`.github/goreleaser.yaml:7`).
Windows amd64 CI не является runtime проверкой ARM64; релиз собирает обе
архитектуры, npm сознательно поставляет amd64 с эмуляцией на ARM64. Версия
parser DLL согласована с go.mod; скачивание DLL из release остаётся без
проверки отдельного ожидаемого digest. Изменять этот workflow ревью не стало.

**Release verdict: NO-GO до исправления P2-1 и объяснённого устранения падений
P2-2 с проверкой итогового кода.** P3-1 не блокирует маленький default list
сам по себе, но должен оставаться открытым без заявления о линейности
structural refresh. Исправления не внесены по условию пользователя. Отчёт
укладывается в лимит 500 строк `.github/CONTRIBUTING.md`; частных локальных
путей, временных probes и изменений других файлов в коммите нет.
