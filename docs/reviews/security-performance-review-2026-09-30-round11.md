# Security and performance review — round 11 — P0–P3

## Вердикт и проверенный срез

**Новых подтверждённых P0/P1 нет. Найден один P2 в сохранении profile record: пропавший source вместе с недоступным каталогом destination превращают неизвестный ответ в успешное забывание существующей копии. P3 с квадратичной работой refresh остаётся; дополнительный разбор показывает также квадратичные Go allocations. Конкретная подстановка неправильного parent из P2 раунда 10 исправлена. Выпуск текущего среза пока не рекомендован.**

База — **`6cb20a333a0ab57952770e0aaa0ca049f55f620e`**. Этот коммит добавляет отчёт round10; предмет проверки включает **16 незакоммиченных profile-файлов**, предоставленных в изолированной review-копии: семь изменённых tracked-файлов и девять новых файлов. Поэтому базовый SHA сам по себе не идентифицирует проверенные изменения. Номера строк ниже относятся к предоставленному рабочему срезу. Production-код, тесты, зависимости и версии ревью не меняло; коммит содержит только этот отчёт.

Семь календарных дней относительно фактической даты HEAD и среды — **17–23 сентября 2026 включительно**: 222 коммита, 199 без merge. Дата `2026-09-30` в имени продолжает последовательность отчётов; коммиты из будущих дней не подразумеваются. Изучены история недели, выводы round9/round10 и текущие пути account → stub → restricted token; ConPTY/conhost/Shield/thread/token; relay/job/lease; ACL/grant/revoke/hard links/path identity; profile copy/cleanup/Plan; check/audit; CI/release. Каждый промежуточный SHA отдельно не собирался.

Локальные проверки: Go `1.26.0 windows/amd64`, небольшие временные fixtures, без UAC, видимых окон, запуска настоящих sandbox accounts и работы с пользовательскими профилями. Новые probe-файлы не создавались. Для новых комбинаций ниже явно отделены статическое доказательство и фактически выполненные тесты.

## P0 — новых подтверждённых находок нет

Порядок запуска сохраняет границу: `setup.Run` отказывает account-less sandbox и берёт slot до `fillProfile` (`internal/cli/setup/run.go:51`, `:72`). `runAsAccount` создаёт stub suspended, назначает job, передаёт lease и сужает process DACL до resume (`internal/win/proc/logon.go:1084`, `:1128`, `:1133`, `:1154`). Stub принимает lease, проверяет birth conhost, создаёт fully restricted token, готовит консоль и вызывает Shield до запуска программы (`internal/sandbox/exec/stub.go:102`, `:165`, `:168`, `:222`, `:254`). Restricted child также назначается в job до resume (`internal/win/proc/run.go:232`).

Restricting SID list и `DISABLE_MAX_PRIVILEGE` остаются в `internal/win/token/restricted.go:133`; account identity берётся из токена sandbox account, буферы user/logon/read SID живут до native calls. Приложенный profile patch не меняет эту цепочку. Нового пути исполнения переданной программы с unrestricted token или записи в чужой файл за пределами заявленной границы не найдено. Это вывод по просмотренному коду и указанным ниже проверкам, не новое account e2e измерение.

## P1 — новых подтверждённых находок нет

| Граница | Проверенное свойство и предел вывода |
| --- | --- |
| Conhost, threads, token | `ShieldConhost` сначала закрывает default DACL токена для будущих threads, затем process и существующие threads (`internal/win/proc/conhost.go:133`). Общий Shield соблюдает тот же порядок (`internal/win/proc/shield.go:147`). Unknown birth-console answer отказывает (`internal/sandbox/exec/console.go:180`). Account/thread e2e локально не запускались. |
| Relay и jobs | HPCON close имеет одного владельца, resize регистрируется под тем же mutex, close ждёт начатые resizes; output drain ждёт EOF с общим ceiling (`internal/sandbox/exec/console.go:504`, `:528`, `:714`, `:796`). Parent закрывает job до обычного bridge drain (`internal/win/proc/logon.go:1171`). Консольные тесты этого среза локально не исполнялись. |
| Lease | `PassTo` дублирует slot handle с нулевым desired access и без наследования, до resume; handoff защищён, сам slot owner-only (`internal/base/lock/slot.go:114`, `:169`, `:340`). Проверена последовательность в коде, без crash/lease e2e. |
| Grant/revoke | Canonical tree lock охватывает ACL операцию (`internal/policy/grant/apply.go:39`, `internal/policy/grant/revoke.go:22`). Group/member lookup errors не становятся успешным отсутствием sandbox identities (`internal/win/acl/owner.go:319`). Descriptor освобождается после чтения owner/ACE; операция владеет parsed SID и Go SID storage. |
| Links и profile | `pathid.Names` признаёт конец только по `ERROR_HANDLE_EOF`; частичная enumeration с ошибкой отказывает (`internal/win/pathid/pathid.go:223`). Проверка destination reparse/hard links находится до truncation (`internal/policy/profile/mirror_file.go:105`, `:128`). External-link refusal, internal-link allowance и отказ Copy при неполной enumeration прошли. |
| Init/account/profile | Замена unopenable account требует creator SID текущего оператора (`internal/sandbox/init.go:372`); MakeProfile проверяет links до изменения ACL, строит подкаталоги через `os.Root`, публикует hive после tightening (`internal/account/ownprofile.go:51`, `:114`, `:162`). Native SID formatter сохраняет typed adapter (`internal/win/sid/sid.go:43`). |
| Check/audit | Check спрашивает Windows через токен sandbox и impersonation copy; ошибка AccessCheck возвращается как ошибка (`internal/win/access/check.go:85`, `:219`). Audit использует один descriptor read и два SID на pass; ACE читаются по порядку, inherit-only не применяется к самому объекту (`internal/win/acl/entries.go:297`, `:413`). Три ACE-order tests и lifetime/counting test прошли. |

Shared desktop/clipboard, сеть, общедоступные writable locations, уже открытые handles и отсутствие межоператорных tree locks остаются ограничениями `docs/limits.md`. Audit двух общих identities не является доказательством эффективных прав полного токена. Ревью не объявляет эти ограничения исправленными.

## P2-1 — missing-source ветка теряет record при неизвестном состоянии destination

**Статус:** новый вывод этого ревью о существующем дефекте; механизм присутствовал до приложенной оптимизации. **Confidence:** высокая для цепочки возвратов и потери record; совместный сценарий новым runtime probe не исполнялся.

**Evidence.** `placeResolver.snapshot` превращает любую ошибку `root.Open` или `ReadDir` в `dirSnapshot{}, false`, не сохраняя её причину (`internal/policy/profile/place_resolver.go:259–276`). `canonicalEntryPath` передаёт такой ответ как отсутствие места (`place_resolve.go:31–34`); `placeIndex.index` не добавляет membership, а `holds` возвращает false (`place_index.go:228–239`, `:299–304`).

Это безопасное «не доказано равенство» для части сравнений, но оно используется и как разрешение забыть прежнюю копию. При ошибке `os.Stat(source)` `copyEntries` сохраняет entry только если `stretch.holds` вернул true; false не сопровождается ошибкой (`internal/policy/profile/copy.go:294–317`, `:346`). Комментарий `:296–309` прямо обещает сохранить ранее скопированные credentials при исчезновении source, однако ошибка чтения destination ломает это обещание.

Минимальная цепочка через публичные функции, следующая из кода:

1. Rules и previous record содержат ровно `agent/auth.json`; destination хранит ранее скопированный файл. Cleanup пуст.
2. Source `agent/auth.json` отсутствует. Каталог destination `agent` нельзя открыть/перечислить, например из-за exclusive directory handle.
3. `forget` видит точно то же написание в current list и пропускает entry без удаления (`internal/policy/profile/forget.go:42–65`).
4. Missing-source ветка строит index; snapshot `agent` возвращает false. Membership пуст, `holds` false, `Copy` возвращает пустой copied list **без ошибки**, хотя destination файл остался.
5. `fillProfile` передаёт `partial=false` в `union`, поскольку `copyErr==nil`; successful branch сохраняет только новый copied list (`internal/cli/setup/run.go:158–175`, `:196–200`). Старый record исчезает.
6. После освобождения каталога `Clear`/`--no-ai` или удаление этого правила уже не знают о файле. Если source остаётся отсутствующим, повторный Copy тоже не восстанавливает утраченный record.

Для условия шага 2 уже есть действующий небольшой Windows fixture: `lockExclusive(..., directory=true)` в `internal/policy/profile/locked_test.go:23`. Выполненные `TestALockedAncestorStopsTheCleanupAndTheRetryClears` и `TestACopyThatCannotAskItsDestinationStopsAndTheRetryCopies` подтвердили отказ открытия закрытого каталога в соседних путях. Они не проверяют missing-source membership branch, поэтому их PASS не закрывает эту находку.

**Impact.** Временная недоступность destination может навсегда вывести существующую credential/config copy из списка файлов для последующего удаления. Запуск ошибочно считается успешным. Это fail-open в учёте и отзыве скопированных данных; внешняя запись, sandbox escape и утечка новых host secrets этой цепочкой не доказаны.

**Recommendation.** Сохранить различие «места нет» / «место известно» / «место не удалось проверить» до решения о copied record. Если неизвестный ответ влияет на сохранение прежнего entry, остановить Copy с ошибкой, чтобы существующий partial-record механизм сохранил возможность retry. Не превращать ошибку destination в отрицательный memo на весь pass и не заявлять владение новыми, никогда не скопированными файлами.

**Tests.** Добавить сочетание missing source + previously recorded nested file + locked destination ancestor. Проверить отказ Copy, сохранение previous record через `fillProfile`, retry после снятия lock и последующий Clear. Контроли: действительно отсутствующая destination, никогда не копировавшийся sandbox-owned файл, case/legacy respelling. Нынешние tests missing-source retention и locked-copy refusal по отдельности PASS; тест их сочетания не найден и не добавлялся по условию ревью.

## P3-1 — refresh сохраняет квадратичные обходы и создаёт квадратичный поток Go allocations

**Статус:** P3-1 round10 остаётся открытым; полный index rebuild из P3-2 round9 убран, общая линейность не достигнута. **Confidence:** высокая для control flow, асимптотики и heap escape; wall-clock влияние и объём native heap не измерялись.

**Evidence, CPU.** `refreshSnapshots` для каждого компонента изменённого пути вызывает `removeSnapshotChild` дважды (`internal/policy/profile/place_index.go:65–103`, особенно `:91–92`). Каждый вызов безусловно проходит `children` через `withoutChild`, даже если имени в slice нет (`:106–123`). При `B` старых соседях и `M` новых root-level именах остаются как минимум `2·M·B` посещений старых детей. При `B=M=E/2` это `Ω(E²)`. Обновление глубокой ветви теперь затрагивает также snapshots её предков. В `retract` остаётся тот же линейный фильтр после каждого удаления (`internal/policy/profile/place_retract.go:134`).

**Evidence, allocations.** Перед обновлением snapshot `refresh` снова спрашивает `resolver.place(path)` (`place_index.go:249`). После предыдущего создания generation уже изменилась; прежний miss следующего имени перепроверяется, но текущий snapshot ещё не содержит только что созданного имени. Alias branch сканирует старых детей, затем очищает `canonicalNames` и заново делает внутренний `map[string]bool` для каждого известного canonical name (`internal/policy/profile/place_resolve.go:76–123`). В mixed fixture это повторяется на последовательных creations, хотя canonical answers старых соседей уже известны.

На форме с `B` неизменными соседями и `M` последовательными creations только такие пересборки дают `Σ(B+j)`, `j=1..M−1`, новых внутренних maps. Для `B=M=E/2` это снова `Ω(E²)` cumulative allocation work; это не утверждение о квадратичной одновременно удерживаемой памяти. Компилятор Go 1.26 подтвердил `place_resolve.go:115: make(map[string]bool) escapes to heap`. Число allocations/op для нового refresh в этом ревью не измерялось.

Дополнительная потеря fast path: `snapshot` возвращает `dirSnapshot` по значению (`place_resolver.go:259–261`). Присваивание `snap.canonicalComplete = complete` (`place_resolve.go:96`) не записывает изменённый bool назад в `r.dirs`; maps сохраняются по ссылке, этот флаг — нет. Поэтому `rebuildCanonical` после refresh видит прежний false и удаляет unique answer вместо восстановления (`place_index.go:133–139`), оставляя последующим alias queries новый scan.

**Impact.** Большой profile list сохраняет квадратичную CPU/GC стоимость после structural changes. Один ReadDir и линейное число resolutions не доказывают линейность всей операции. Для небольшого default list это не самостоятельный security blocker.

**Recommendation.** Обновлять child set и canonical membership адресно, не фильтровать весь slice по отсутствующему имени и не пересоздавать все внутренние maps при очередном alias scan. Сохранять completeness в том snapshot, который будут читать следующие операции. Не ослаблять проверку filesystem identity или корректность partial scans ради counters.

**Tests.** `TestAMixedCopyRefreshesStructuralMirrorsWithoutReindexingTheRecord` PASS при 4/8 entries: один resolver, один ReadDir, `children=E/2`, `resolutions=2E−1`. Эти assertions не считают `withoutChild` visits, повторные canonical-map rebuilds, heap allocations и все resolution opens. Добавить именно эти счётчики/малые allocation assertions и сравнение с новым resolver после каждой mutation. Высокая нагрузка и benchmarks не запускались.

## Закрытие round9/round10 и оставшиеся пределы refresh

| Прежний вывод | Статус на рабочем срезе |
| --- | --- |
| Round9 P3-1: Plan пропускает запрещённый cleanup при nil destination | Закрыт: `refuseReservedCleanup` стоит перед nil-root return (`internal/policy/profile/cleanup.go:50–59`). Четыре соответствующих preview/Plan tests PASS. |
| Round10 P2-1: место прежнего miss подставляется как parent изменённого leaf | Конкретный механизм исправлен: `refresh` сохраняет непосредственный parent пути, а `miss.directory` использует только как dependency (`place_index.go:245–273`); `refreshSnapshots` проходит цепочку компонентов. Новый public-Copy test с locked unrelated basename PASS. |
| Round9 P3-2 / round10 P3-1: повторная индексация и quadratic work | Полная переиндексация устранена на mixed fixture. Обходы cached children и allocations остаются P3-1 этого отчёта. |
| Ранее закрытые reserved-ancestor/preflight/retract случаи | Hive alias test с 13 subtests, оба Copy preflight tests, excluded-child partial clear и terminal-leaf retraction PASS. |

Закрытие конкретного wrong-parent обращения не означает полной эквивалентности refresh свежему index. Новый `TestCopyRefreshUsesMutationParentInsteadOfMissDependency` (`place_alias_test.go:192`) копирует **файл** `parent/nested` и дополнительно создаёт parent через resolver seam после snapshot. Он не закрепляет первоначальный directory-entry сценарий `prepareDir` с несколькими отсутствующими предками. `TestPlaceIndexDoesNotKeepAMissAcrossCreateOrDelete` проверяет subtree refresh и case variant, но не legacy miss aliases.

Отмеченный в round10 alias gap по коду остаётся: trie индексирует записанные сегменты через uppercase (`place_index.go:167–195`). Ранее отсутствовавший record `file.` не попадает в `byPath.under("file")`; после создания `file` generation может устарить miss, но `members` для такого record не заполняется. Аналогично `parent./file` при creation `parent`. Только miss generation не исправляет presence set. Это статическое продолжение прежнего differential observation; успешный публичный Copy с потерей record именно из-за этого варианта в round11 не воспроизведён, отдельный P2 о его последствиях не заявляется. При доработке refresh нужны fresh/incremental comparisons для ancestor creation, directory replacement, exclusions, aliases и удаления.

## Производительность и владение памятью вне refresh

| Область | Вывод |
| --- | --- |
| Profile bytes | Один lazy 32 KiB scratch на Copy, bounded stream и проверка изменения source сохранены (`mirror_file.go:67`, `:139`, `:182`). Оба соответствующих tests PASS. Нет нового process-wide cache с содержимым credentials. |
| Resolver memory | Operation-local maps, reverse books, membership sets и trie удерживают записи/компоненты путей и snapshots каталогов. `ReadDir(-1)` держит весь посещённый каталог. Экономия повторного I/O не является ограничением памяти всего profile tree константой. |
| Revoke memo | `[68]byte` scratch принадлежит одной операции; name lookup memo keyed по SID bytes, native `CopySid` остаётся на каждом eligible lookup (`internal/win/acl/reclaim.go:290`, `:321`, `:362`). `TestARepeatAnswerAsksNothingAndAllocatesNothing` PASS: hit дешевле fresh-buffer key и не добавляет allocations относительно shared-scratch key. Название теста не доказывает нулевых native/Go затрат каждого вызова. |
| Path identity | Canonical/name enumeration начинает с 256 UTF-16 slots и растёт по ответу Windows, отказывает на ошибке/неподходящем размере (`pathid.go:78`, `:93`, `:223`). Общая стоимость OutsideNames зависит от числа hard-link names и глубины ancestor checks (`:282`). |
| ACL sweep | Ordered write stage ограничивает outstanding work кредитами (`internal/win/acl/sweep.go:123`). Это не `O(window)` память всего sweep: `WalkDir` и pinned snapshot имеют собственную стоимость. SID storage и native descriptors освобождаются владельцем операции; новых lifetime нарушений в приложенном patch не найдено. |
| Warm grant/audit | Grant record использует path index (`internal/policy/state/index.go`); audit разрешает два SID один раз и читает descriptor объекта один раз. Это локальные улучшения соответствующих операций, не обещание линейности любого списка вложенных grants. |

## Выполненные проверки

**38 top-level PASS, 1 SKIP**, без широкого project suite. Все тестовые запуски: `-count=1 -p=1 -parallel=1`, по явному списку имён. Subtests не посчитаны как отдельные top-level PASS.

| Пакет / предмет | Результат |
| --- | --- |
| `internal/policy/profile`: новый parent refresh, miss create/delete, mixed structural/warm, rewrite, partial scan, nil-root preview/Plan, preflight, reserved aliases, partial clear, terminal leaf, hard links, copy budget и scratch | 20 PASS; 4/8-entry functional fixtures, не benchmark. |
| `internal/policy/profile`: missing-source retention/respelling и два соседних locked-copy отказа | 4 PASS. Комбинация P2-1 не входила в эти существующие tests. |
| `internal/win/sid`: formatter failure, CurrentUser failure, typed bytes formatting | 3 PASS. |
| `internal/win/pathid`: partial enumeration refusal, Copy refusal, canonical buffer growth и ceiling | 4 PASS. |
| `internal/win/acl`: три ACE-order tests, две unknown group/member проверки, scratch memo allocation test, audit read/lifetime test | 7 PASS. |
| `TestATakeBackRemembersARefusedLookupOnlyAsItsNarrowing` | Честный SKIP: recovery требует отсутствующую `SeRestorePrivilege`. За полный PASS этот тест не засчитан. |
| `go vet ./internal/policy/profile` | PASS. |
| `go test ./internal/policy/profile -run '^$' -gcflags='-m' -p=1` | Компиляция PASS; escape diagnostics подтверждают heap maps выше. Это не runtime allocation benchmark. |
| `git diff --check` | PASS для предоставленных tracked changes. |
| `gofmt -l` / `gofmt -d` только 16 profile-файлов | Девять добавленных файлов отмечены из-за одной лишней пустой строки в конце каждого; иных formatting diffs нет. Код не форматировался по условию ревью. |

Account, registry-hive, real conhost/thread, lease-crash и own-console e2e локально не запускались. Нулевых SKIP для всего sandbox здесь не заявляется; heap profile и native heap measurements не делались.

## CI и условия выпуска

Для **базы** найден успешный [tests run 35861732387](https://github.com/PHPCraftdream/wuserbox/actions/runs/35861732387), созданный `2026-09-23T12:38:14Z`, на точном SHA `6cb20a333a0ab57952770e0aaa0ca049f55f620e`. Через GitHub API проверены success шагов `Delete boundary`, `Registry hive picture`, `Own console measurement`. Это обновляет сведения о CI из прошлых ревью, но **не покрывает 16 незакоммиченных profile-файлов**.

`.github/workflows/ci.yml` запрещает SKIP и проверяет наличие нужных PASS в специальных gates. Release запускается отдельно по tag; GoReleaser hook выполняет общий `go test ./...`, без обязательного ожидания этих gates и без own-console opt-in (`.github/workflows/release.yml:3`, `.github/goreleaser.yaml:7`). Успешного общего release hook недостаточно для подтверждения итоговой границы. Formatting gate также не примет предоставленные девять новых файлов до удаления лишних завершающих пустых строк; это замечание к точному review-срезу, не функциональная регрессия.

Все 16 приложенных profile-файлов имеют **менее 500 строк**; максимум — 488. Этот отчёт тоже короче 500 строк. Старые большие файлы вне patch не переписывались. Приоритет лимита строк над приблизительным числом файлов пакета прямо установлен `.github/CONTRIBUTING.md`.

**Решение о выпуске:** устранить P2-1 с постоянным совместным regression test, проверить оставшиеся refresh differential cases и получить CI итогового коммита с обязательными boundary/hive/own-console gates. P3-1 не блокирует безопасность небольшого списка сам по себе, но остаётся открытым и не позволяет объявить structural refresh линейным. Базовый зелёный CI, 38 локальных PASS и исправление прежнего wrong-parent пути не заменяют эту проверку актуального кода.
