# Security and performance review — round 9 — P0–P3

## Вердикт и срез

**Новых подтверждённых P0/P1/P2 нет. Пять находок раунда 8 закрыты на проверенном срезе. Открыты два P3: неверный успешный `--dry-run` для cleanup при ещё не созданном профиле и квадратичный путь повторного индексирования при чередовании структурных копий с исчезнувшими источниками.** Безусловную готовность к релизу не подтверждаю: для итогового SHA нет CI с обязательными boundary, registry-hive и own-console gates. После исправления P3-1 нужен CI итогового SHA; P3-2 не является блокером для небольшого списка профиля.

Проверен `d54761b705a25a5d5bffb7ab6b8b031351712561`. Семь календарных дней относительно даты этого HEAD — **17–23 сентября 2026 включительно**: 220 коммитов, из них 197 без merge. Дата `2026-09-29` в имени отчёта продолжает последовательность review-файлов; коммитов за 24–29 сентября в проверенной истории нет. Раунд 8 проверял `e67a380` (22 сентября); между ним и HEAD — исправления всех пяти его находок и тесты. История недели, прошлые ревью и текущий код прослежены по account → stub → fully restricted token, ConPTY/conhost/Shield/threads, relay/job/lease, ACL/grant/revoke/links/path identity, profile copy/cleanup, CLI check/audit и CI/release. Каждый промежуточный SHA отдельно не собирался.

Production-код не менялся. Адресные проверки шли на временных файлах, без UAC, видимых окон, искусственной нагрузки и изменений пользовательских профилей. Номера строк ниже относятся к указанному HEAD.

## P0 — новых подтверждённых находок нет

Проверены порядок передачи lease в suspended stub (`internal/win/proc/logon.go:824, 845`), ограничение токена и применение Shield до запуска программы (`internal/sandbox/exec/stub.go`, `internal/win/token/restricted.go`, `internal/win/proc/shield.go`), назначение job до `ResumeThread` (`internal/win/proc/run.go:232`, `internal/win/proc/logon.go`), защита host process/token/threads (`internal/win/proc/conhost.go:133`) и пути, по которым ACL или profile copier могут коснуться файла вне границы (`internal/win/acl/links.go:28`, `internal/win/pathid/pathid.go`, `internal/policy/profile/mirror.go`). Нового проверенного способа выполнить программу с неограниченным токеном или переписать внешний файл не найдено. Это вывод о проверенных путях, не замена e2e под настоящей учёткой.

Адресный probe для подозрительной ветви `mirrorFile` с hard link внутри временного профиля на внешний временный файл не подтвердил fail-open: при обычной ACL метаданные читались и `OutsideNames` отказал в копировании; с запретом чтения `Lstat` отказал, но и `OpenFile` отказал до truncation. Probe не доказывает невозможность другого сочетания ACL и sharing flags, поэтому на его основе P0/P1 не заявляется.

## P1 — новых подтверждённых находок нет

Ранее закрытый SID native-adapter остаётся типизированным (`internal/win/sid/sid.go`); новых переходов Go pointer → `uintptr` через interface в изменениях раунда 9 нет. Account/conhost/registry boundary e2e в этом раунде не исполнялись: им нужны административные условия и часть включает настоящую консоль. Их отсутствие не выдаётся за PASS.

## P2 — новых подтверждённых находок нет

Обе потери данных из раунда 8 закрыты в коде и адресными тестами:

| Прежняя находка | Evidence на HEAD | Проверка |
| --- | --- | --- |
| Legacy record с alias в предке мог удалить `UsrClass.dat` | `pathSuspicious` теперь смотрит **каждый** сегмент (`internal/policy/profile/reserved.go:179`); `resolvedRootRel` разделяет absent/resolved/unknown (`:232`); оба guard отказывают в удалении при неизвестном ответе (`:297, :325`) | `TestATakeBackSparesTheHiveARecordSpelledTheWayTheVolumeReadsIt`: 13 subtests PASS, включая alias в каждом предке и удаление родительского каталога. Контрольный нерезервный файл удаляется. Отдельный junction/refusal test SKIP: локальная машина не создала junction. |
| Неверный profile entry обнаруживался после cleanup/forget | `refuseEntriesCopyRefuses` проверяет весь список через `within` (`internal/policy/profile/refusals.go:181–199`) до обеих удаляющих стадий (`internal/policy/profile/copy.go:50–76`); `Plan` использует тот же preflight (`preview.go:55`) | `TestCopyRefusesAnEntryThatCannotLandBeforeTakingAnythingBack` и `TestCopyRefusesTheWholeListBeforeTheFirstEntryMoves`: оба PASS, включая валидный первый и невалидный второй entry. |

Оставшийся P3-1 ниже касается другого списка — `cleanup` при отсутствующей destination — и не открывает снова второй P2: реальный `Copy` отказывает до cleanup, ошибочен только предварительный ответ `Plan`.

## P3-1 — `Plan` принимает запрещённый cleanup при отсутствующем профиле

**Статус:** новый подтверждённый диагностический дефект прежнего кода. **Confidence:** высокая для расхождения `Plan`/`Copy`; влияние ограничено предварительным выводом.

**Evidence.** `internal/policy/profile/preview.go:59–68` открывает несуществующий `dest` как `root=nil`. Затем `previewCleanup` в `internal/policy/profile/cleanup.go:62–75` возвращает пустой план при `root==nil` **раньше** `refuseReservedCleanup`. Реальный `Copy` в `copy.go:50–76` вызывает `clearCleanup`; тот проверяет `refuseReservedCleanup` до обхода. Временный probe на одном правиле `cleanup: [NTUSER.DAT]` дал `plan_refused=false, copy_refused=true` после создания destination. Probe удалён после измерения. Существующий тест `TestThePlanOfAMissingDestinationAsksTheSuspiciousNameAsWritten` проверяет profile entries, но не этот cleanup refusal. Это более узкий остаток старого класса `Plan`/`Copy` расхождений (release review round 10, P3-6): общий preflight уже закрыл entries, не ветку nil-root cleanup.

**Impact.** `--dry-run` новой песочницы обещает допустимый запуск с пустым cleanup-планом, а реальный запуск отказывает. Защита hive при настоящем копировании остаётся на месте; данные этим случаем не удаляются. Оператор тратит запуск/инициализацию и получает позднее сообщение об ошибке правила.

**Recommendation.** Проверять `refuseReservedCleanup(cleanup)` до возврата по `root==nil`; отсутствие destination означает ноль совпадений, а не разрешение запрещённого glob. Сохранить тот же отказ для `Plan` и `Copy` на `NTUSER.DAT`, `**`, предках `UsrClass.dat` и допустимый no-match для обычного glob.

**Tests.** Добавить постоянный тест публичного `Plan` с отсутствующим destination и запрещённым cleanup, затем контроль `Copy` после создания временной destination; сравнить класс отказа и убедиться, что обычный cleanup остаётся пустым планом. Временный probe выполнился PASS как измерение дефекта, не как тест исправленного поведения.

## P3-2 — структурные изменения всё ещё пересоздают индекс для каждого следующего missing source

**Статус:** остаточная стоимость в `copyEntries`, не регрессия пяти исправлений раунда 8. **Confidence:** высокая для асимптотики по управлению потоком, средняя для влияния на реальное время; wall-clock и большой fixture не измерялись.

**Evidence.** `internal/policy/profile/copy.go:278–358` строит `newPlaceIndex(root, recorded)` при первом отсутствующем источнике каждой mutation-free серии и обнуляет `stretch` после `mirror` с `changed=true`. `newPlaceIndex`, `internal/policy/profile/fold.go:812–820`, вновь разрешает **все** `E` recorded entries. При `M` чередующихся структурных mirror и missing-source вопросов это `O(M·E)` повторных разрешений, а при `M=Θ(E)` — `Θ(E²)`. Смена байтов существующего файла индекс уже сохраняет; этот случай исправлен раньше и сюда не входит. Структурные изменения нельзя игнорировать: creation/replacement может сделать прежний miss ложным. Тестов со счётчиками именно этой чередующейся формы в текущем наборе не найдено.

**Impact.** Большой вручную заданный profile list на первом запуске после массовых структурных изменений может заплатить повторными ReadDir, canonicalization и Go allocations за индексы. У небольшого default list это не release blocker и не ослабление ACL.

**Recommendation.** Сначала закрепить 4/8-entry fixture счётчиками `resolutions`, `children`, `opens`, а затем рассмотреть адресную инвалидизацию созданных/удалённых имён или обновление индекса после mirror. Не сохранять отрицательные ответы через создание имени. Сравнить результат с новым resolver и проверить exclusions/alias spellings.

## Производительность и закрытие P3 раунда 8

| Область | На текущем срезе |
| --- | --- |
| Partial-forget с exclusions | `retract` оставляет parent snapshot при подтверждённом существовании entry (`internal/policy/profile/fold.go:700–781`). `TestAClearThatSparesAnExcludedChildLeavesTheHoldingDirectoryStanding` PASS при `E=4,8`: один resolver, один ReadDir, `children=E`, `visits=E/2`. Прежняя измеренная сумма `E·(E/2+1)` устранена для этого fixture. |
| Stale terminal leaf | `notePlace` регистрирует canonical leaf в reverse index (`fold.go:385–409`), `retract` удаляет его memo при обходе поддерева (`:700–743`). `TestRetractReachesATerminalLeafBeneathTheTakenDirectory` PASS. |
| Revoke scratch | `trusteeAnswers` владеет одним `[68]byte` scratch (`internal/win/acl/reclaim.go:290–365`); `TestARepeatAnswerAsksNothingAndAllocatesNothing` PASS относительно прежнего fresh-buffer варианта. `CopySid` всё ещё вызывается на каждом eligible ACE до memo lookup, а variadic `LazyProc.Call` может выделять память. Один `sandboxGroup` name lookup на distinct SID остаётся целью; нулевых Go allocations на hit тест не обещает. |
| Профиль | Постоянный warm-copy без структурных изменений использует один resolver и индекс; один 32 KiB scratch выделяется при первом переносе байтов (`internal/policy/profile/mirror.go`). Cleanup проходит только достижимые glob ветви, но `ReadDir(-1)` держит список одного каталога целиком. Новый preflight профиля — линейный проход по `E` entries и их сегментам/маскам. |
| ACL и path identity | Инициализация существующего дерева требует как минимум `O(N)` просмотра объектов и hard-link names. `Isolate` имеет read-only preflight и write sweep; `Prune`/`TakeBack` проходят затронутое дерево. `pathid` начинает с малого буфера и растёт по ответу Windows. Уменьшать эти проходы без нового доказательства границы нельзя. |

Здесь `E` — число profile entries, `M` — число структурных mirror между вопросами о пропавшем источнике, `N` — число объектов дерева. Счётчики для partial-forget — маленькие функциональные fixtures, а не искусственная нагрузка или wall-clock benchmark.

## Остальные проверенные границы

- Account → stub → restricted token: `setup.Run` берёт slot до `fillProfile` (`internal/cli/setup/run.go:23–83`); `RunAsAccountWithLease` передаёт handle suspended stub (`internal/win/proc/logon.go:824–845`); stub принимает его до Shield, создаёт restricted token и лишь затем запускает child. `Check` строит token настоящей учётки (`internal/cli/diagnose/check.go:29`, `internal/win/token/logon.go`); старый account-less путь не выдаётся за account boundary.
- ConPTY/relay/job: relay отдаёт close одному владельцу и ждёт начатые resizes (`internal/sandbox/exec/console.go:504–584`); output drain ждёт EOF, а job закрывается до bridge drain (`internal/win/proc/logon.go`). Birth, own и relay conhost получают process/token/thread shield до запуска программы (`internal/win/proc/conhost.go:133`, `internal/sandbox/exec/stub.go`). Число потоков и окна в этом ревью не форсировались.
- ACL/grant/revoke/path identity: `Apply`/`Revoke` держат canonical tree lock; `ValidateLinks` и `pathid.Names` не принимают частичную hard-link enumeration; profile copier использует `os.Root` и повторную проверку ссылок до truncation. `TakeBack` memo ограничен одной операцией, native SID/descriptors освобождаются; `Prune` и sweep не проходят reparse point как каталог.
- CLI/release: `--check` спрашивает access check токена, `--audit` лишь диагностирует Everyone/Users ACL и не управляет enforcement (`internal/cli/inspect/audit.go:31`). CI берёт Go из `go.mod`, имеет отдельные no-SKIP boundary, seeded-hive и own-console gates (`.github/workflows/ci.yml`). Release hook запускает общий `go test ./...`, но сам по себе не заменяет эти gates (`.github/goreleaser.yaml`). Ограничения из `docs/limits.md` — shared desktop, сеть, уже открытые handles, общедоступные writable locations — остаются границами продукта.

## Выполненные проверки и выпуск

| Проверка | Результат |
| --- | --- |
| Profile: limited partial-forget, terminal leaf, legacy alias, два path-preflight tests, unknown-resolution fixture | 5 top-level PASS; 1 SKIP (junction на этой машине не создан). Alias test: 13 subtests PASS. |
| ACL revoke memo/allocations | 2 top-level PASS; 1 SKIP (нужен SeRestorePrivilege). SKIP оставил временный ACL fixture, убрать его без этой привилегии тест не смог. |
| Временный probe `Plan`/`Copy` на отсутствующем профиле и forbidden cleanup | PASS как измерение: `false/true` по отказам; файл probe удалён. |
| Временный hard-link/ACL probe | Два варианта PASS как измерения отказа; внешний временный файл не изменился; файл probe удалён. |
| `gh run list --commit d54761b…` | Пусто: CI этого HEAD отсутствует. Последний найденный успешный [tests run 35823648792](https://github.com/PHPCraftdream/wuserbox/actions/runs/35823648792) относится к `4c73923`, до всех пяти исправлений раунда 8. |

Итого постоянных адресных тестов: **7 PASS, 2 SKIP**; временные probes не являются регрессионными тестами исправленного поведения. Полный suite, lint/vet, настоящий account/conhost e2e и видимая own-console проверка этого SHA локально не запускались. Перед релизом: исправить P3-1, получить CI итогового SHA с обязательными gates и учесть два локальных SKIP. P3-2 измерить на небольшом воспроизводимом fixture до оптимизации; выпуск по безопасности он не блокирует.
