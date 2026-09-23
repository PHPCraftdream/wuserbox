# Security and performance review — round 10 — P0–P3

## Вердикт и проверенный срез

**Новых подтверждённых P0/P1 нет. Найден один P2: обновление profile index после создания вложенного каталога может открыть посторонний одноимённый файл и остановить исправный Copy. Один P3 остаётся открытым: повторное полное индексирование устранено, но обновление списка соседей сохраняет квадратичную работу.** P3-1 раунда 9, успешный Plan с запрещённым cleanup при отсутствующей destination, закрыт. Выпуск приложенного incremental refresh пока не рекомендован: исправить P2, закрепить новые случаи и получить обязательные CI gates на итоговом коде.

База — `b26c48cb967bfded8c3930bba6b0a981fed2daab`, который добавляет только отчёт round9 поверх `d54761b705a25a5d5bffb7ab6b8b031351712561`. Проверены также **16 незакоммиченных profile-файлов** с исправлениями round9: cleanup refusal до nil-root return, журнал structural mutations, поколения directory snapshots и инкрементальный place index. Содержимое совпало с основной рабочей копией; девять добавленных файлов в предоставленной review-копии отличаются только дополнительным завершающим LF. Номера строк ниже относятся к этому срезу, не к одному базовому SHA.

Неделя относительно фактического HEAD: **17–23 сентября 2026 включительно**, 221 коммит, 198 без merge. Дата `2026-09-29` в имени продолжает последовательность отчётов; будущие коммиты не подразумеваются. Прослежены история изменений и текущие пути account → stub → restricted token, ConPTY/conhost/Shield/threads, relay/job/lease, ACL/grant/revoke/hard links/path identity, profile copy/cleanup, CLI check/audit и CI/release. Каждый промежуточный SHA отдельно не собирался.

Production-файлы не менялись. Единственный сохраняемый результат ревью — этот отчёт. Проверки использовали небольшие временные fixtures, Go `1.26.0 windows/amd64`, без UAC, видимых окон, искусственной нагрузки и работы с пользовательскими профилями. Временный probe удалён после измерений.

## P0 — новых подтверждённых находок нет

В просмотренных путях не найден новый способ запустить переданную программу без ограничения токена или записать наружу через profile maintenance. Stub создаётся suspended, назначается job, получает lease и закрытый process DACL до resume (`internal/win/proc/logon.go:845`, `:1128`, `:1133`, `:1154`). `Stub` принимает lease, закрывает birth host, строит restricted token, готовит консоль и вызывает Shield до запуска программы (`internal/sandbox/exec/stub.go:102`, `:165`, `:168`, `:222`, `:254`). `runInJob` назначает child в job перед resume (`internal/win/proc/run.go:232`).

Проверены `DISABLE_MAX_PRIVILEGE` и полный restricting-SID список (`internal/win/token/restricted.go:133`, `:178`), lifetime SID buffers и освобождение native SID. Account identity в restricting list берётся у токена sandbox account; legacy account-less путь остаётся отличным от реального account boundary. `setup.Run` отказывает в запуске без account и берёт slot до fillProfile (`internal/cli/setup/run.go:23`, `:72`). Новая profile-оптимизация этих границ не меняет.

## P1 — новых подтверждённых находок нет

- `ShieldConhost` закрывает будущие threads через token default DACL, process и уже существующие threads; неопределённая birth-host диагностика отказывает (`internal/win/proc/conhost.go:133`, `internal/win/proc/shield.go:278`, `internal/sandbox/exec/console.go:180`). Native SID formatter сохраняет типизированный adapter с конкретным `LazyProc.Call` (`internal/win/sid/sid.go:43`).
- Lease дублируется в suspended stub без read/write access и без наследования; handoff защищён, исходный slot закрыт read group (`internal/base/lock/slot.go:114`, `:169`, `:340`). Parent закрывает job до обычного bridge drain. В relay только один владелец HPCON close; начатые resizes заканчиваются до освобождения, output drain ждёт EOF с ограничением общего teardown (`internal/sandbox/exec/console.go:504`, `:528`, `:714`).
- ACL update и revoke держат canonical tree lock, identity lookup группы и её members не превращает неизвестный ответ в успешное отсутствие (`internal/policy/grant/apply.go:39`, `internal/policy/grant/revoke.go:22`, `internal/win/acl/owner.go:319`). Descriptors живут до конца чтения owner/ACE, операция владеет SID storage; sweep ограничивает outstanding work кредитами, write stage сохраняет порядок (`internal/win/acl/sweep.go:123`).
- Hard-link enumeration заканчивается успешно только на `ERROR_HANDLE_EOF`; ошибка после части имён не разрешает передачу (`internal/win/pathid/pathid.go:223`). Profile copy проверяет внешние hard links и reparse destination до truncation, сохраняет `os.Root` и bounded stream (`internal/policy/profile/mirror_file.go:67`, `:111`, `:128`, `:182`). Адресные external-link и internal-link проверки PASS.

Это проверка кода и перечисленных локальных fixtures. Настоящие account/conhost/thread/registry boundary e2e в этом раунде не исполнялись. Shared desktop, сеть, уже открытые handles, общедоступные writable locations и отсутствие межоператорных tree locks остаются описанными ограничениями `docs/limits.md`; они не выдаются здесь за новые обходы или закрытые границы.

## P2-1 — refresh вложенного каталога принимает место прежнего miss за непосредственного родителя

**Статус:** подтверждённая регрессия приложенного incremental refresh. **Confidence:** высокая: воспроизведена через публичный `Copy`, дополнительно сравнением со свежим индексом. Ошибка fail-closed; выход из sandbox и потеря пользовательских файлов не показаны.

**Evidence.** `copySink.prepareDir` отмечает только `dst`, затем `MkdirAll` может создать сразу несколько компонентов (`internal/policy/profile/mirror.go:180`). Файловая ветка уже отмечает верхнего отсутствующего предка (`:296`), но directory branch этого не делает. Если snapshot построен до появления `parent`, запрос `parent/nested` получает miss в `.`. `placeIndex.refresh` подставляет `miss.directory` в `parent` (`internal/policy/profile/place_index.go:208`, `:219`). `refreshMutation` собирает `Join(parent, Base(path))` (`:15`, `:17`): в этом случае получается **`nested` в корне**, а не `parent/nested`.

Публичный probe использовал ровно два profile entries и три небольших файла:

1. Rules и previous record: `[anchor, parent/nested]`.
2. Destination: `anchor` и посторонний файл `nested`; каталога `parent` ещё нет. Source: только `parent/nested/source` с текстом `copied`.
3. Посторонний destination `nested` открыт через `CreateFile` с share mode 0. Это обычный exclusive hold временного файла, без изменения ACL.
4. Missing source `anchor` строит индекс; следующий mirror успешно создаёт `parent/nested/source`. Затем публичный `Copy` возвращает ошибку `refreshing profile resolver after mirror changed parent\nested: openat nested: ... being used by another process`.

Измерено: `copy_refused=true`, `copied=[anchor parent/nested]`, содержимое `parent/nested/source="copied"`. Файл вне этой ветви блокирует запуск только потому, что refresh спрашивает не тот путь. В базовом `b26c48c` после structural mirror `stretch` сбрасывался; нового обращения к постороннему `nested` там нет. Отдельный probe без locked sibling дал для recorded `parent/nested` после создания и `refresh("parent/nested")`: **incremental holds=false, fresh index holds=true**.

**Impact.** Обычная вложенная directory entry на создании или восстановлении профиля может отказать после успешного копирования из-за чужого одноимённого файла в корне. Без этого файла обновлённый resolver всё равно отличается от реального дерева. Ошибка останавливает запуск; `fillProfile` сохраняет объединённый partial record (`internal/cli/setup/run.go:164`), поэтому этот probe не доказывает забытые credentials или ошибочное удаление. Наличие partial record не исправляет выбор чужого пути.

**Recommendation.** Directory mirror должен сообщать все созданные компоненты, либо верхнего созданного предка с полной инвалидизацией его зависимостей, как файловая ветка. При восстановлении пути нельзя считать первый каталог, в котором lookup остановился, непосредственным родителем последнего компонента. Проверять актуальное имя по всей оставшейся цепочке, затем обновлять snapshots и membership из этой цепочки.

**Tests.** Закрепить публичный `Copy` для двух и более новых directory components, с unrelated locked basename в корне и без него. Проверить новый и уже существующий parent, его case alias, file→directory replacement, exclusions и удаление. После каждой операции сравнивать `holds` обновлённого и нового индекса, а не только counters. Временный probe здесь PASS как измерение существующего дефекта; это не регрессионный тест исправления. Новые штатные `TestPlaceIndexDoesNotKeepAMissAcrossCreateOrDelete` и `TestARewriteKeepsTheStretchAndACreatedNameEndsIt` PASS, но первый обновляет `nested` целиком, второй создаёт файл непосредственно в корне: ни один не покрывает `prepareDir` с отсутствующим предком.

**Дополнительный предел проверки aliases.** Tiny differential с первоначально отсутствующим recorded `parent./file`, созданием `parent/file` и `refresh("parent")` тоже дал `false/true`; аналогично `file.` → создание `file` → `refresh("file")`. `byPath.under` индексирует записанные компоненты через uppercase, не связывая ещё не разрешившийся legacy alias с новым stored name (`place_index.go:130`, `:151`); поколение miss может устареть, но `members` само от этого не заполняется. Это отдельный наблюдаемый пробел эквивалентности индекса. Его следует включить в differential tests при исправлении refresh. Успешный публичный Copy с потерей record именно из-за этого alias-варианта не воспроизведён; отдельная находка о потере данных не заявляется.

## P3-1 — обновление соседей сохраняет O(E²), хотя ReadDir и resolutions уже линейны

**Статус:** P3-2 раунда 9 закрыт только в части повторных resolver/index builds и I/O; общая асимптотика не исправлена. **Confidence:** высокая для механизма и числа обходов, влияние на wall-clock не измерялось.

**Evidence.** `refreshMutation` дважды вызывает `remove(name)` при успешной creation; каждый `remove` вызывает `withoutChild`, который просматривает весь сохранённый `children` slice даже при отсутствии удаляемого имени (`internal/policy/profile/place_index.go:42`, `:53`, `:56`, `:79`). При `B` неизменных соседях и `M` новых именах это как минимум `2·M·B` проверок имён. В fixture с чередующимися missing sources и structural mirrors `B=M=E/2`, то есть сохраняется `Ω(E²)` работы по соседям. Alias scan добавляет свои обращения.

Небольшой probe обернул исходные `os.DirEntry` в счётчик вызовов `Name()` и создал отсутствующую половину имён по одному через `refresh`. Wrapper возвращал настоящее имя и не менял ответы resolver:

| Recorded entries E | Изначальных соседей B | Созданий M | ReadDir | children counter | resolutions | Вызовов Name() сохранённых соседей |
| --- | --- | --- | --- | --- | --- | --- |
| 4 | 2 | 2 | 1 | 2 | 7 | 14 |
| 8 | 4 | 4 | 1 | 4 | 15 | 52 |

Последний столбец включает `withoutChild` и alias scans; это не число файловых opens. Он показывает работу, отсутствующую в текущих counters. Постоянный `TestAMixedCopyRefreshesStructuralMirrorsWithoutReindexingTheRecord` PASS на обоих размерах: один resolver, одно чтение каталога, `resolutions=2E−1`. Улучшение по I/O реально, но комментарий про линейный mixed run (`place_index.go:113`) и закрытие общей квадратичности этими assertions не подтверждаются. Линейное уплотнение sibling slice также остаётся в `retract` после удаления (`place_retract.go:134`); это старый соседний путь, а не новая регрессия.

**Impact.** Большой вручную заданный список профиля сохраняет квадратичную CPU-работу после structural changes. На небольшом default list это не security blocker. Уменьшение числа системных вызовов полезно, но не означает O(E) всей операции.

**Recommendation.** Обновлять набор соседей по ключу либо использовать tombstones/индекс позиций и уплотнять один раз за pass; как минимум не фильтровать slice, если имя в нём отсутствует. Сохранить точность alias/canonical indexes и поведение неполного sibling scan. Добавить счётчик реально просмотренных cached children, чтобы O(E²) нельзя было спрятать за одним ReadDir. Не заменять свежесть отрицательных ответов экономией обходов.

**Tests.** Постоянный 4/8-entry fixture должен считать scans/Name visits вместе с opens, resolutions, memberships и allocations; сравнивать полученные ответы со свежим resolver. В этом раунде большие fixtures и wall-clock benchmark не запускались.

## Производительность, allocations и закрытые регрессии

| Область | Результат проверки |
| --- | --- |
| Missing destination cleanup | `previewCleanup` проверяет reserved glob до nil-root return (`internal/policy/profile/cleanup.go:50`, `:54`, `:57`). Четыре адресных теста Plan/preview с `NTUSER.DAT`, `**/UsrClass.dat` и ordinary no-match PASS. P3-1 round9 закрыт на рабочем срезе. |
| Warm profile hits | На неизменном индексе повторный exact `holds` дал **0 Go allocations** при E=4 и E=8. Полное создание текущего index — **102/166 allocations** соответственно (`testing.AllocsPerRun(1)`, warm-up и одна измеряемая итерация, четыре/восемь однобайтовых файлов). Это локальные числа для данного fixture/toolchain, не обещание всем paths. |
| Новая память index | `paths`, вложенные `members` и trie добавляют operation-local maps и компоненты путей; память зависит от E и суммарной глубины (`place_index.go:116`, `:130`, `:176`, `:191`). Экономия повторных построений сопровождается этой ценой; B/op не измерялся. |
| Copy bytes | Сохраняются один ленивый 32 KiB scratch на Copy и проверка размера открытого source до truncation; поток ограничен бюджетом. `TestOneScratchBufferServesTheWholeCopyNotEachFile` и growth-after-measurement test PASS. |
| Partial forget / leaf retract | Тесты exclusions при E=4/8 и terminal leaf под удалённым каталогом PASS; ранее закрытые ошибки round8 не воспроизвелись. Счётчик reverse-book visits не измеряет уплотнение sibling slice. |
| Revoke memo | `[68]byte` scratch принадлежит `trusteeAnswers`, lookup memo ограничен одной TakeBack (`internal/win/acl/reclaim.go:290`, `:321`, `:362`). Каждый eligible ACE всё ещё вызывает CopySid до memo lookup; нельзя обещать нулевые allocations всего native-call path. Нового измерения этого неизменённого участка не выполнялось. |
| ACL / links / audit | Sweep остаётся как минимум O(N) по объектам, максимум 8 classifier workers и окно `2·workers`; preflight и write sweep — разные проходы. Перечисление L hard-link names с проверкой ancestry глубины d добавляет O(L·d) вопросов. Audit читает descriptor один раз на объект и применяет ACE по порядку; Check использует AccessCheck токена. Ни одна диагностика не заменяет enforcement. |

## Выполненные проверки

Постоянные тесты запускались двумя адресными `go test ./internal/policy/profile -run '^(...names...)$' -count=1 -v`, **30 top-level PASS, 0 FAIL, 0 SKIP**. Подтесты не прибавлялись к числу 30.

- 14 тестов изменённого resolver/preview: `TestPreviewCleanupChecksReservedGlobsWithoutADestination`, `TestPreviewCleanupAllowsANonmatchingGlobWithoutADestination`, `TestThePlanOfAMissingDestinationRefusesReservedCleanup`, `TestThePlanOfAMissingDestinationLeavesAnOrdinaryNoMatchCleanupEmpty`, `TestAMixedCopyRefreshesStructuralMirrorsWithoutReindexingTheRecord`, `TestPlaceIndexDoesNotKeepAMissAcrossCreateOrDelete`, `TestARewriteKeepsTheStretchAndACreatedNameEndsIt`, `TestAClearThatTookNothingBackKeepsTheStretchAndOneThatClearedRetractsItsAnswers`, `TestAliasAnswersAreKeptForTheQuestionsThatFollow`, `TestAScanThatSkippedASiblingDoesNotPoisonTheOnesItKept`, `TestAWarmCopyPaysResolverWorkOncePerEntryNotOncePerPair`, `TestAWarmForgetCountsChildrenOncePerStretchNotOncePerQuestion`, `TestDedupeEntriesResolvesEachEntryOnce`, `TestSameEntryPlaceSharesOneLookBetweenItsTwoSpellings`.
- 16 проверок соседних profile гарантий: `TestAClearThatSparesAnExcludedChildLeavesTheHoldingDirectoryStanding`, `TestRetractReachesATerminalLeafBeneathTheTakenDirectory`, `TestATakeBackSparesTheHiveARecordSpelledTheWayTheVolumeReadsIt`, `TestCopyRefusesAnEntryThatCannotLandBeforeTakingAnythingBack`, `TestCopyRefusesTheWholeListBeforeTheFirstEntryMoves`, `TestCopyRefusesAnExternalHardLinkBeforeTruncatingIt`, `TestCopyAllowsHardLinksWhoseNamesStayInTheProfile`, `TestCopyReconcilesADirectoryToMatchItsSource`, `TestAnExclusionSparesTheDestinationsSpellingOfAName`, `TestAMirrorSparesTheHiveUnderADirectoryTheSourceHasLost`, `TestACopyPastItsBudgetRefusesWhenTheSourceGrowsAfterItWasMeasured`, `TestOneScratchBufferServesTheWholeCopyNotEachFile`, `TestALockedCopyStopsTheRunAndTheRetryTakesTheCopyBack`, `TestACopyThatCannotAskItsDestinationStopsAndTheRetryCopies`, `TestALockedAncestorStopsTheCleanupAndTheRetryClears`, `TestALockedBranchNoGlobCanReachDoesNotStopTheCleanup`.

Временные probes отдельно измерили public-Copy refusal, fresh/incremental divergence, cached-child visits и allocations; их успешный exit означает успешное измерение, не исправность найденного поведения. Все их файлы и handles закрыты, probe source удалён. Полный project suite, race, lint/vet, elevated account/registry/conhost e2e и own-console tests не запускались.

## CI, размер файлов и release verdict

`gh run list --commit b26c48cb967bfded8c3930bba6b0a981fed2daab` вернул пустой список. Последний найденный успешный [tests run 35823648792](https://github.com/PHPCraftdream/wuserbox/actions/runs/35823648792), созданный 23 сентября в 05:44:16 UTC, относится к `4c739230a97cd61412e550d629d3555f6d402855`: он предшествует пяти исправлениям round8 и всем текущим незакоммиченным правкам. Старый зелёный run не подтверждает этот срез.

CI берёт Go из `go.mod`; отдельные `Delete boundary`, `Registry hive picture`, `Own console measurement` запрещают SKIP и требуют совпадения ожидаемых PASS (`.github/workflows/ci.yml:55`, `:136`, `:194`). Release запускается отдельно по tag и выполняет общий `go test ./...` через GoReleaser hook, без этих специальных gates и без зависимости от tests job (`.github/workflows/release.yml:1`, `.github/goreleaser.yaml:7`). Поэтому зелёный release hook сам по себе не заменяет проверку безопасности итогового SHA. Версии проекта и зависимостей ревью не меняло.

Проверка требования `.github/CONTRIBUTING.md`: каждый из 16 приложенных изменённых profile-файлов — **не более 488 строк**, этот отчёт — **менее 500 строк**. Число файлов в package выросло при разделении; CONTRIBUTING прямо отдаёт приоритет лимиту строк перед приблизительным числом файлов каталога. `git diff --check` для исходных tracked changes прошёл; production files в коммит отчёта не включены.

**Решение:** исправить P2-1 и проверить весь refresh на эквивалентность свежему resolver, включая указанные miss/alias варианты. P3-1 не блокирует безопасность небольшого профиля, но закрывать его как общую линейность нельзя. Затем нужен CI финального коммита с обязательными account boundary, seeded-hive и own-console gates; локальные 30 PASS не заменяют эти ещё не выполненные проверки.
