# Security and performance review — 2026-09-24 — round 4 — P0–P3

## Вердикт и проверенный срез

**Выпуск как готовой файловой песочницы пока не рекомендован: открыты три P1.**
Два блокера раунда 3 остаются в production-коде; дополнительно найден путь,
который при ошибке разрешения SID продолжает изменение ACL с неполным списком
идентичностей песочницы. Подтверждённого нового P0 в этом раунде нет. Это не
утверждение, что побегов не существует: атакующие программы и воспроизведение
побегов в этом ревью не запускались.

Открыто: **P0 — 0; P1 — 3; P2 — 3; P3 — 2.** Новые относительно раунда 3:
P1-3 и P2-3. Прежний P2 про видимое окно shield-thread fixture закрыт по коду.
Нумерация ниже относится к этому отчёту, связь со старыми пунктами дана явно.

Проверен **`93ae09ae482cabb8c83d3fa4681603d974116be9`**. У его HEAD дата
22 сентября; последние семь календарных дней этого среза — **16–22 сентября
2026 включительно, 201 коммит**. Дата в имени отчёта — обозначение раунда,
а не утверждение о наличии в истории коммитов за 24 сентября. История
просмотрена по подсистемам; отдельного полного аудита каждого промежуточного
коммита не проводилось. Номера строк относятся к проверенному HEAD.

Просмотрены account → stub → restricted process, birth/relay/own-console hosts,
Shield и жизненный цикл потоков, jobs/lease, relay drain/resize/cleanup,
ACL/grant/revoke/owner cap, hard links, profile copy/cleanup/path identity,
тесты и release workflows. Сопоставлены
[раунд 3](security-performance-review-2026-09-23-round3.md),
[раунд 2](security-performance-review-2026-09-22-round2.md) и
[первый отчёт](security-performance-review-2026-09-20.md).

Работа выполнена в отдельной worktree. Production-код и существующие тесты
не менялись. Единственный добавленный файл — этот отчёт. Локально выполнены
22 адресных обычных теста и compiler escape analysis трёх пакетов. UAC,
административные account e2e, видимые окна, пользовательские проекты,
нагрузочные и эксплуатационные эксперименты не использовались.

## Что изменилось после предыдущего ревью

| Пункт / подсистема | Состояние на проверенном HEAD |
| --- | --- |
| Round 3 P1-1: owner SID после освобождения descriptor | Открыт без изменения механизма: P1-1 ниже. |
| Round 3 P1-2: синхронный relay close вне deadline | Открыт без изменения механизма: P1-2 ниже. |
| Round 3 P2-1: warm-forget O(E²) | Открыт: P2-1 ниже. |
| Round 3 P2-2: частично неизвестный conhost oracle | Открыт: P2-2 ниже. Исправлено место запуска probe, но не агрегация неизвестных результатов. |
| Round 3 P2-3: видимый shield-thread subprocess | Прежний прямой os/exec запуск удалён. Fixture запускается через RunAsAccount с CREATE_NO_WINDOW; конкретный пункт закрыт по коду. |
| Round 3 P3-1 / P3-2: выбрасываемый heldEntry / SID lifetime | Оба открыты; P3-1 / P3-2 ниже. |
| Admin fixtures | `19e297f`, `0c05909`, `108b25f` дают shield-тестам реальную account seat и корректные положительные контроли. Это существенное улучшение доказательства. |
| Relay helper identity | `94759f3` передаёт shutOut явно; production Stub передаёт свой CurrentUser, а поведенческие tests используют отдельный SID. Подмена production identity в этом изменении не обнаружена. |
| Диагностика и CI | `7292699` добавляет сведения к отказу thread shield, не превращая отказ в успех. `48576bb` исправляет путь probe; `93ae09a` убирает утечку SeRestorePrivilege из cleanup теста. |

**CI этого SHA действительно зелёный:**
[run 35717911572](https://github.com/PHPCraftdream/wuserbox/actions/runs/35717911572),
headSha сверён полностью. Из лога шага Delete boundary получено **80 PASS,
0 SKIP**; Own console measurement также success. Этот факт заменяет устаревшую
оговорку раунда 3 об отсутствии зелёного CI на проверенном срезе. Зелёный CI
не снимает найденные ниже ошибки, для которых нет нужного отрицательного
контроля.

## P1-1 — ACL preflight возвращает owner SID из освобождённого descriptor

**Статус:** повторно подтверждён, Round 3 P1-1. **Confidence: высокая.**

**Evidence.** `internal/win/acl/sweep.go:461` — readable;
`:469` — deferred Free descriptor; `:471` и `:477` — возврат ownerOf(descriptor)
как uintptr. `internal/win/acl/owner.go:260` получает адрес SID внутри
descriptor. Затем `sweep.go:357` принимает этот адрес, а `:374` сравнивает его
через ownedByTheSandbox после того, как readable уже выполнил Free.

Это native use-after-free, независимо от поведения Go GC. Контракты
[GetSecurityDescriptorOwner](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorowner)
и [GetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow)
подтверждают, что SID заимствован из возвращённого descriptor.

**Impact.** При непустом keep-list preflight может неверно определить владельца,
не сохранить необходимую identity до изменения ACL и затем отказать в середине
операции; возможен native crash. Из этой ошибки отдельно не доказан обход
границы: дальнейшее narrowing читает owner заново, а неоднозначная identity
в pinned fallback должна остановить операцию. Поэтому P1, не заявленный P0.

**Recommendation.** Внутри readable, пока descriptor жив, проверить допустимость
ACE и вычислить owned bool; наружу вернуть bool/error. Не возвращать наружу
ни owner uintptr, ни heldEntry с trustee pointers этого descriptor. Это
одновременно позволяет закрыть P3-1 без дополнительной SID allocation.

**Tests.** Нужен проверяемый порядок «сравнение owner до освобождения descriptor»
или API, который вообще не выпускает заимствованный адрес из lifetime.
Успешный snapshot test и Go race detector не доказывают безопасность native
памяти. После исправления обязательны адресные pinned/narrow/revoke проверки.
Native heap corruption в этом раунде намеренно не провоцировалась.

## P1-2 — relay finish всё ещё может сам войти в блокирующий close

**Статус:** повторно подтверждён, Round 3 P1-2. **Confidence: высокая по порядку
вызовов; live hang в этом раунде не измерялся.**

**Evidence.** `internal/sandbox/exec/console.go:646` запускает finish;
`:656` — отдельную goroutine для closeConsole. Владение HPCON помечается
только внутри closeConsole (`:521`), а не до запуска goroutine. Ветки готового
drain (`:678`) и drain на границе timeout (`:688`) вызывают relay.close;
close (`:545`) снова синхронно вызывает closeConsole.

Следовательно, при уже завершённом drain и ещё не вошедшем close-worker
главный путь может первым забрать HPCON и выполнить native close. После этого
select уже не ограничивает длительность teardown. Проблема относится также
к error-return Stub: `stub.go:203` оставляет deferred relay.close.
До Windows 11 24H2 ClosePseudoConsole может не вернуться при недренируемом
output pipe; на более новых системах сигнал завершения вывода также не
равен возврату этого вызова.
[Контракт ClosePseudoConsole](https://learn.microsoft.com/en-us/windows/console/closepseudoconsole).

**Impact.** Потенциально неограниченный teardown и удержание run slot после
завершения программы. Исправленная ранее resize/free гонка остаётся закрытой:
это другой дефект — выбор исполнителя блокирующего close.

**Recommendation.** Синхронно перевести ресурс в closing и передать исключительное
право native close одному worker до любого select. Остальные cleanup paths
закрывают только разрешённые им pipe ends и не могут стать новым владельцем
native close. Ожидание in-flight resize и close остаётся под общим бюджетом;
sync.Once, заставляющий остальных ждать блокирующего Do, задачу не решает.

**Tests.** Два существующих console-free теста порядка resize/close и ceiling
прошли здесь. Они удерживают drain незавершённым и дают worker забрать HPCON;
обратный порядок не измеряют. Нужен детерминированный контроль с drain,
завершившимся до захвата close-worker, включая последующий deferred cleanup.
Проверять следует владение ресурсом и ограниченный возврат функции, без
необходимости зависать в настоящем conhost.

## P1-3 — ошибка разрешения SID превращается в успешную неполную identity list

**Статус:** новая находка этого раунда. **Confidence: высокая по error-path;
сбой Windows lookup в живой песочнице здесь не воспроизводился.**

**Evidence.** `internal/win/acl/owner.go:172` accountNameOf возвращает
`name, err == nil`, теряя причину любой ошибки sid.Name. В sandboxIdentities
(`:150`) false возвращает успешный список только из исходного SID. Для
production-вызовов это SID группы, а не SID учётки, которая владеет файлами.
`internal/win/acl/sweep.go:637` BeginStripOwn повторяет ту же ветку.

Кроме того, `internal/win/sid/sid.go:61` не сохраняет код ошибки первого
LookupAccountSidW; нулевая длина на `:63` выдаётся за not found. Отказ чтения,
сбой разрешения и действительно неназначенный тестовый SID становятся одной
ситуацией. Документированный lookup возвращает отдельный статус отказа;
даже ERROR_NONE_MAPPED может сопровождать timeout разрешения, а не только
доказанное отсутствие principal.
[LookupAccountSidW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidw).

**Impact.** Если такая ошибка возникает для существующей группы песочницы,
Isolate/TakeBack продолжают работу без SID её account: сравнения owner
(`reclaim.go:130`, `sweep.go:288`, `:516`) перестают узнавать принадлежащие
песочнице объекты; удаление explicit account ACE также перестаёт их узнавать.
Операция может успешно завершиться с более слабым narrowing/revoke, чем
обещано. Это fail-open при неизвестном результате identity lookup. Умение
недоверенной программы вызвать такую ошибку и реальный обход доступа этим
путём не установлены; находка не объявляется подтверждённым P0.

**Recommendation.** Сохранять errno и разделить «разрешённая identity»,
«допустимый сам по себе SID» и «неизвестный результат». Для известной
production sandbox group не разрешать успешный group-only fallback после
ошибки lookup. Практичный вариант — operation context с явно проверенными
group/account SID; synthetic SID fixtures могут иметь отдельный явный путь.
Не исправлять это подавлением ещё одного класса ошибок в accountNameOf.

**Tests.** Нынешний TestTheIdentitiesFailClosedWhenTheAccountIsNotSIDText
(`pinned_test.go:433`) проверяет синтаксис SID и не достигает lookup. Нужны
обычные инъекционные тесты отказа на обоих этапах разрешения: identity builder
возвращает ошибку до первого ACL write, а BeginStripOwn не создаёт usable pass.
Положительный тест синтетического SID следует сохранить отдельно. Проверка
errno не требует создания учётки, UAC или запуска недоверенной программы.

## P2-1 — неизменный warm-forget остаётся квадратичным

**Статус:** открытый Round 3 P2-1. **Confidence: высокая.**

**Evidence.** `internal/policy/profile/forget.go:24` обходит прежние entries,
`:30` создаёт resolver для каждого; stillNamed (`:285`) снова проходит current
с начала и строит presence map. Проверка точного spelling находится внутри
этого прохода, после всех предыдущих entries. Для совпадающих списков из E
существующих разных файлов это E(E−1)/2 обращений place, даже без удаления
или respelling. Каждый новый resolver снова перечисляет общий каталог
(`fold.go:300`) и строит byName (`:306`). При E children в нём суммарная
обработка directory entries и allocation traffic остаются O(E²).

Ветка missing source (`copy.go:303`, `:350`) аналогично создаёт fresh resolver
и canonical set на каждый entry. Alias cache уменьшает повторные opens,
но проход всех siblings на каждый новый alias (`fold.go:363`) остаётся.

**Impact.** Warm startup повторяет работу на неизменном наборе. Результаты
маленького measurement probe 4/8 entries из раунда 3 не выдаются за новый
замер: здесь подтверждена та же структура, существующий six-entry perf test
повторно PASS. Его счётчики Open/ReadDir не считают число children, обработанных
каждым ReadDir(-1); этот PASS совместим с квадратичной работой.

**Recommendation.** Один cleaned-spelling set current перед циклом forget
сразу делает обычный unchanged path O(E). Один resolver и canonical-presence
index на участок без мутаций; инвалидировать после реального clear/mirror,
не после каждого вопроса. Для missing-source vouches аналогично переиспользовать
индекс на неизменяемом участке. Для разных alias — индекс canonical path →
единственный stored name/ambiguity вместо повторного сканирования siblings.

**Tests.** Считать resolutions и суммарное число children snapshot, не только
количество вызовов ReadDir. Достаточно нескольких entries; большой benchmark
не нужен. Сохранить проверки разных hard-link names, Unicode identity,
respelling, удаления между вопросами и восстановления неполного record.

## P2-2 — conhost oracle допускает частично неизвестный результат

**Статус:** открытый Round 3 P2-2. **Confidence: высокая.**

**Evidence.** `internal/e2e/conhost_test.go:277` сохраняет неизвестные process
errors в notes. На `:309` неизвестность отдельно обрабатывается лишь когда
неопределённы все process doors. Ошибка OpenProcessToken после успешного
OpenProcess (`:294`) не классифицируется. Для потоков notes заполняются
на `:393`/`:406`, но итоговое unmeasured на `:441` равно только examined == 0.
Один определённо проверенный поток позволяет пройти мимо неопределённости
другого живого потока. Верхний verdict проверяет open/unmeasured, а notes
сами по себе не делают его неуспешным.

**Impact.** Обязательный CI guard может пройти при неполном измерении.
Это дефект регрессионного доказательства; он не означает, что production
Shield пропускает те же обращения. Исправления account seat, пути бинарника
и stderr полезны, но данный путь агрегации они не меняют.

**Recommendation.** Неизвестность учитывать по каждой обязательной операции.
Неизвестный ответ по живому объекту завершает измерение отдельной ошибкой.
Исчезновение объекта подтверждать отдельно; ошибки process-open и token-open
не объединять. Положительные до-Shield controls и before/between/after
thread fixtures сохранить.

**Tests.** Pure verdict test с одной определённой и одной неизвестной
обязательной проверкой должен быть неуспешным. Отдельно — token-open error
после успешного process-open. Эти тесты можно сделать без windows, аккаунтов
и реальных опасных открытий процессов.

## P2-3 — потолок profile copy проверяет старый Stat, а не объём копирования

**Статус:** новая находка этого раунда. **Confidence: высокая по механизму;
живое изменение источника между Stat и Open здесь не запускалось.**

**Evidence.** `internal/policy/profile/mirror.go:222` вычитает info.Size из
бюджета до копирования. Затем `:244` вызывает mirrorFile без бюджета;
`:256` заново открывает source, `:293` копирует его через неограниченный
io.Copy. Количество реально прочитанных/записанных байтов не проверяется.
FileInfo получен раньше, в copyEntries (`copy.go:286`) либо walkDir
(`mirror.go:88`). Источник может вырасти или быть заменён другим обычным
файлом между этими точками. Последующая Print также использует прежние
size/mtime (`mirror.go:251`).

**Impact.** При изменяющемся источнике один успешный проход способен записать
больше объявленных 64 MiB, а длительность переноса не ограничена исходной
оценкой. Это ошибка ресурсного ограничения и возможное возвращение роста
профилей, не обход os.Root или файловой границы. Обычная пользовательская
запись в source достаточно объясняет условие; атакующий сценарий не нужен.

**Recommendation.** Сохранить логический бюджет для всего списка, включая
skipped files, и дополнительно ограничить реальный поток копирования.
Информацию для fingerprint брать относительно открытого source и подтверждать
стабильность нужных metadata; при изменении — отказ/повтор без успешной Print.
Повторный Stat сам по себе не даёт лимита потока. Неполный перенос должен
по-прежнему оставлять entry в record для последующей очистки.

**Tests.** Существующие два ceiling-теста PASS на неизменных маленьких файлах.
Нужен маленький детерминированный тест stale FileInfo: после получения info
источник имеет больше байтов, чем оставшийся бюджет; операция отказывает,
не выдаёт успешную Print и не пишет сверх заданного лимита. Бюджета в несколько
байтов достаточно, создавать 64 MiB или нагрузочный writer не требуется.

## P3-1 — validation-only preflight выделяет heldEntry и сразу выбрасывает его

**Статус:** открытый Round 3 P3-1. **Confidence: высокая.**

**Evidence.** `sweep.go:357` отбрасывает slice readable, но readable всё равно
вызывает entriesOf, где `entries.go:97` выделяет slice по числу ACE.
Текущий compiler escape analysis подтверждает выход make([]heldEntry, ...)
на heap. Следующий classify pass вновь читает и разбирает ACL.

**Impact.** O(Σ Aᵢ) дополнительного allocation traffic для N объектов с Aᵢ ACE.
Число workers ограничивает одновременно живую часть, но не суммарный GC traffic.

**Recommendation / tests.** Вместе с P1-1 сделать validation walk по ACE и
сравнение owner внутри lifetime descriptor, без сохранения slice. Проверки
неподдерживаемого ACE/GetAce failure и отказа до первого write должны остаться.
Контролировать удаление конкретной allocation, не фиксировать случайное общее
число allocations всех Windows wrappers.

## P3-2 — native SID lifetime остаётся process-wide вне audit/StripOwn

**Статус:** открытый Round 3 P3-2. **Confidence: высокая.**

**Evidence.** sid.Parse выделяет native SID и имеет явный sid.Free, однако
успешные Set/Deny/Remove (`internal/win/acl/set.go:72`, `:178`, `:189`),
Isolate (`isolate.go:61`) и TakeBack (`reclaim.go:43`) не завершают lifetime.
TakeBack уже первый parsed SID использует только для проверки синтаксиса.
sandboxIdentities держит member buffers в глобальном pinned (`owner.go:186`);
fromNothing (`isolate.go:232`) выделяет ещё три SID на NULL-DACL объект.

**Impact.** Для короткого CLI цена обычно небольшая, но native heap и global
pin растут с числом операций/соответствующих объектов. Go allocs не измеряют
LocalAlloc. Исправленные WritablePass и StripOwnPass имеют более короткое
владение; их lifetime-счётчиковые тесты здесь прошли.

**Recommendation / tests.** Перенести уже имеющийся operation context на
Isolate/TakeBack, вместе с исправлением identity error-path P1-3: один набор
SID/Go buffers до завершения всех workers и последнего Windows вызова,
затем явное освобождение. Для коротких Set/Deny/Remove — scoped Free.
Проверить баланс native parses/frees на success/error и отсутствие роста
global pins за несколько операций. Не вставлять Free, пока lifetime
заимствованных uintptr не определён.

## Сложность и порядок улучшений

Первый grant неизвестного существующего дерева с нынешним механизмом требует
как минимум Ω(N) чтений объектов: каждый может иметь собственный ACL или
внешний hard link. Исключать target/node_modules ради ускорения нельзя.
Параллельное чтение уменьшает ожидание диска, не эту нижнюю границу.

У текущего sweep bounded reorder window действительно ограничен W, но полная
память прохода не O(W): identity snapshot остаётся O(S), где S — число
объектов, чьё владение требует snapshot; в худшем случае S=N. WalkDir и
ReadDir(-1) удерживают списки детей каталогов. Дополнительно pinned.prepare
(`pinned.go:163`) делает проверку каждого path против списка pinned entries:
при большом P это O(NP) сравнений, даже когда Windows resolutions уже сокращены.
Для обычного малого P не стоит менять это раньше исправления P1.

Наиболее ясное снижение O сейчас — P2-1: exact-spelling set и snapshot/index
на участок без мутаций убирают повторную работу на unchanged warm run.
P3-1 уменьшает allocations на каждом объекте без смены порядка ACL writes.
P3-2 и P1-3 естественно решаются одним строго владеющим identity context.

256-element UTF-16 buffer в pathid действительно заменил прежнюю безусловную
64 KiB allocation. Compiler всё ещё отправляет его на heap через syscall seam;
это меньшая allocation, не нулевая. Межзапусковый mutable path cache ради её
устранения не оправдан: identity надо подтверждать после изменения дерева.
Аналогично нельзя объединять preflight с первым write ради одного прохода:
отказ до изменения ACL — отдельная гарантия.

Не доказано, что количество Go apply calls равно полной стоимости NTFS:
наследуемые ACL также распространяются Windows. Без измерения native работы
нельзя обещать линейную стоимость всех вариантов дерева или ускорение в 4–8 раз.
Больших benchmarks этот раунд не запускал; процентных обещаний не даёт.

## Проверки и приёмка релиза

Локальная среда: Go 1.26.0, windows/amd64. **22 top-level PASS, 0 SKIP**:

| Пакет | Адресная проверка | Результат |
| --- | --- | --- |
| internal/sandbox/exec | Console-free resize/close ordering и hung-close ceiling; три birth-list guard cases | 5 PASS |
| internal/policy/profile | Dedupe/resolver/alias; selective cleanup; два обычных ceiling cases | 6 PASS |
| internal/win/acl | StripOwn identity lifetime; WritablePass lifetime/count; два inherit-only cases | 6 PASS |
| internal/win/pathid | EOF/error enumeration; grown-buffer error; Canonical bounds | 5 PASS |
| Compiler escape analysis | acl/profile/pathid, -gcflags=-m=2 | Успех; heldEntry и snapshot maps на heap, initial UTF-16 buffer на heap |

Это повторная проверка существующих обычных регрессий. Новые fault-injection
tests из рекомендаций в этом review-only раунде не добавлялись. Полный suite
локально не запускался; его success и обязательные account/console шаги
подтверждены чтением уже завершённого CI именно на проверенном SHA.

В test/release одинаковый go-version-file. Boundary список проверяет skip и
число PASS. Own-console opt-in остаётся отдельным CI-шагом. Release workflow
может запускаться на tag независимо от main CI; hook GoReleaser с обычным
go test не заменяет обязательный no-skip boundary и own-console шаг на том
же выпускаемом SHA. Перед публикацией нужен именно этот результат для кода
с исправлениями P1 и обновлённым oracle P2-2.

Рекомендуемый порядок: **P1-1 и P1-3 в ACL lifetime/identity → P1-2 teardown →
P2-2 полнота oracle → P2-1/P2-3 и P3 оптимизации**. Для аккуратной работы
доверенных CLI продукт уже даёт дополнительную файловую защиту, но этот срез
нельзя рекомендовать как законченную границу против враждебного кода.

Общедоступные Everyone/Users writable directories, разрешённое чтение,
сеть, desktop/clipboard и ранее открытые file handles остаются опубликованными
пределами модели. В этом раунде они не пересчитаны как новые уязвимости;
также ими нельзя оправдывать fail-open identity lookup, native use-after-free
или неограниченный teardown.
