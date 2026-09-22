# Security and performance review — 2026-09-23 — round 3 — P0–P3

## Вердикт и срез

**Релиз проверенного среза пока блокируют два P1.** Подтверждённого нового
побега P0 в этом раунде не найдено. Это не доказательство отсутствия побегов:
полная цепочка с реальной учёткой здесь повторно не запускалась. Новая оптимизация
ACL содержит native use-after-free, а исправление relay teardown оставляет
ветку, в которой блокирующий close снова оказывается вне deadline.

Открыто: **P0 — 0; P1 — 2; P2 — 3; P3 — 2.** P0 означает подтверждённый обход
заявленной файловой границы; P1 — существенную ошибку безопасности памяти или
запуска/завершения; P2 — функциональный дефект, пробел обязательного измерения
или заметную проблему производительности; P3 — более локальную оптимизацию.
Возможные последствия отдельно от доказанного механизма не повышают пункт до P0.

Проверен `eeab4d631f2df8fe9f39b8cef676e6449da61b57`. Просмотрена история за
16–22 сентября включительно: 188 коммитов, семь календарных дней, содержащих дату
этого HEAD. Сравнение исправлений — с
[раундом 2](security-performance-review-2026-09-22-round2.md) и
[первым отчётом](security-performance-review-2026-09-20.md). История просмотрена
по изменениям подсистем; отдельного полного аудита каждого промежуточного SHA
не было. Ссылки `файл:строка` далее относятся именно к проверенному HEAD.

Разобраны account → stub → fully restricted process, birth/relay/own-console
hosts, Shield и потоки, jobs/lease, stdio и teardown, grant/revoke/owner cap,
hard links, профиль/copy/cleanup, path identity, тесты и release workflows.
Работа шла в отдельной worktree. Production-код не изменён; сохранён только
этот отчёт. Обычные адресные проверки использовали временные тестовые объекты;
административные account e2e, UAC, видимые окна и нагрузочные эксперименты
не запускались.

## Что исправлено после раунда 2

| Пункт раунда 2 | Состояние на этом срезе |
| --- | --- |
| P1-1: timeout после блокирующего ClosePseudoConsole | `9b4208b` переносит close в goroutine и включает его в бюджет. Основной путь исправлен, но передача владения не завершена до select: P1-2 ниже. |
| P1-2: resize после освобождения HPCON | `9b4208b` закрывает вход под mutex, учитывает вошедшие resize через WaitGroup и освобождает HPCON после их выхода. Прежняя гонка по коду устранена; адресный тест порядка PASS. |
| P2-1: ошибка GetConsoleProcessList считалась отсутствием host | `eeab4d6` возвращает неизвестную ошибку до ограничения токена/Run. Разрешённый no-console случай выделен по ERROR_INVALID_HANDLE. Три адресных теста guard PASS. |
| P2-2: один поток и любая ошибка OpenThread считались доказательством shield | `415efad` перечисляет все потоки, проверяет два вида доступа и отдельно измеряет потоки, родившиеся до/между/после этапов Shield. Осталась частично неизвестная выборка, которую oracle считает успехом: P2-2 ниже. |
| P2-3: own-console leg показывал окно в обычном suite | `ab26360` ставит opt-in на этот leg и отдельный обязательный CI-шаг. Старый конкретный пункт закрыт. В новом тесте появился другой незащищённый запуск: P2-3 ниже. |
| P2-4: quadratic warm-copy | `9a1cb8a` действительно сокращает повторное перечисление внутри одного вопроса, но вопросы по-прежнему строятся заново на каждый entry. Остаточная квадратичность измерена: P2-1 ниже. |
| P2-5: inherit-only ACE применялся к самому каталогу | `41a6a76` исключает InheritOnly из holdsAny. Прежняя причина устранена. |
| P3-1: весь pinned snapshot оставался O(N) | `80accec` хранит в sweep только sandbox-owned объекты и уменьшает revoke snapshot под pinned ветками. Worst case O(N) честно остаётся; новая реализация передаёт наружу уже освобождённый SID: P1-1 ниже. |
| P3-2: launch trace включал runtime | `e967f36` разделяет create/resume/wait/job_close/bridge_drain, переименовывает общий интервал в command_lifetime, добавляет pid/run. Прежний дефект закрыт по коду. |
| P3-3: audit перечитывал ACL и выделял SID на объект | `41a6a76` даёт WritablePass с одной descriptor read и двумя SID на проход. Два счётчиковых теста PASS; исправление audit не объявляется открытым повторно. |

Исправления первого раунда также остаются в силе: fully restricted token,
hard-link enumeration с различением EOF/ошибки, bounded reorder window,
canonical tree-lock root, начальные UTF-16 буферы по 256 элементов и selective
cleanup. Оснований снова объявлять эти конкретные дефекты открытыми не найдено.

## P1-1 — owner SID используется после LocalFree его security descriptor

**Evidence.** Новая ветка `80accec`:

- `internal/win/acl/sweep.go:461`: `readable` получает descriptor через
  GetNamedSecurityInfoW и на строке 469 ставит `defer w32.Free(descriptor)`;
- строки 471 и 477 возвращают `ownerOf(descriptor)` как `uintptr`;
- `internal/win/acl/owner.go:260`: ownerOf получает адрес SID внутри этого
  descriptor; копирования SID здесь нет;
- `internal/win/acl/sweep.go:357` и `:374`: уже после возврата из readable
  inspect передаёт адрес в ownedByTheSandbox → matchesSandboxIdentity → EqualSid.

Go выполняет defer перед возвратом управления вызывающему. Следовательно,
EqualSid читает освобождённую native память всякий раз, когда pinned.keys
непуст и owner проверяется. Это не отсутствие runtime.KeepAlive: память
явно возвращена Windows через LocalFree, и KeepAlive этого не исправит.
Контракты [GetSecurityDescriptorOwner](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getsecuritydescriptorowner)
и [GetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow)
подтверждают, что возвращается адрес внутри descriptor, а не отдельная копия.

**Impact / confidence.** Высокая уверенность в use-after-free по времени жизни.
До восьми параллельных ACL readers могут переиспользовать native блок между Free
и EqualSid. Следствия — неверная классификация владельца, потеря нужной записи
pre-change snapshot и отказ последующего narrowing после того, как часть ACL
уже изменена; возможен native crash. Сам последующий cap повторно читает owner
из живого descriptor, а pinned fallback отказывает при недоступной identity.
Поэтому из этой находки не следует доказанный fail-open или P0 escape.
Падение процесса и эксплуатация управления heap в этом раунде не провоцировались.

**Recommendation.** Вычислять `owned bool` внутри readable, пока descriptor жив,
и возвращать bool/error. Альтернатива — явно владеющая копия SID, но здесь
она не нужна: caller использует только результат сравнения. Одновременно
убрать возвращаемый `[]heldEntry`: его trustee pointers тоже заимствованы из
освобождаемого descriptor; сейчас caller их отбрасывает, но API оставляет
опасную форму доступной следующей доработке.

**Tests.** Два новых snapshot sweep-теста проходят и на этом дефекте: после
LocalFree старые байты часто остаются на месте. Нужен lifetime oracle, который
утверждает, что owner сравнивается до освобождения descriptor, либо проверка
варианта с собственным SID после гарантированной порчи/освобождения источника.
Обычный Go race detector native LocalFree/EqualSid не контролирует. После
исправления повторить pinned/narrow/revoke boundary, включая owned sealed subtree.

## P1-2 — drain-first ветка снова может выполнить ClosePseudoConsole синхронно вне deadline

**Evidence.** `internal/sandbox/exec/console.go:647`: finish запускает goroutine
закрытия на строках 657–660, затем выбирает между closed/waited/timer.
При готовом waited на строке 679 вызывается `relay.close()`. Такой же вызов
есть в timer/drain ветке на строке 689. `close()` на строке 546 синхронно
вызывает closeConsole. Флаг hpcClosed устанавливается лишь тем вызовом
closeConsole, который первым получил mutex (`:513`).

Допустимый порядок выполнения:

1. Output pump уже завершился, например с ошибкой consumer; waited закрыт.
2. Goroutine, созданная для close, ещё не получила процессор либо ещё не
   завладела mutex. Создание goroutine не гарантирует завершения этого шага.
3. finish выбирает waited и сам входит в relay.close → closeConsole.
4. Главный путь первым присваивает hpcClosed и оказывается внутри native close;
   другая goroutine позже увидит closed и сразу вернётся.

Таймер уже существует, но главный путь больше не находится в select.
До Windows 11 24H2 ClosePseudoConsole может блокироваться, если output pipe
не дренируется; ошибочный consumer как раз заканчивает io.Copy, оставляя
непрочитанный поток. См. [контракт ClosePseudoConsole](https://learn.microsoft.com/en-us/windows/console/closepseudoconsole).
Комментарий «instant no-op on the console» предполагает порядок, которого
код не устанавливает. Возможен и неограниченный Wait за resize в этом же close.

**Impact / confidence.** P1: hang teardown и удержание slot после завершения
программы. Высокая уверенность в допустимом interleaving и отсутствии общего
deadline в нём; воспроизведения live hang со сломанным consumer здесь не было.
Прежняя resize/free гонка закрыта: этот пункт о том, какой поток может стать
владельцем блокирующего close, а не о повторном free.

**Recommendation.** Синхронно забрать право закрытия и пометить HPCON closing
до запуска worker и до select; само ожидание in-flight resize и native close
оставить worker. Cleanup после выбора должен закрывать только допустимые pipe
ends и никогда не становиться первым исполнителем native close. У разных
путей закрытия должен быть общий completion signal. Простой sync.Once.Do,
который ждёт завершения чужого Do, вернёт исходное неограниченное ожидание.

**Tests.** Существующие resize/ceiling-тесты PASS. Их drain специально не
завершается до timeout, давая close-worker время забрать ресурс. Добавить
детерминированный противоположный порядок: drain уже завершён с ошибкой,
close-worker удержан до захвата владения, finish должен вернуть ошибку в
бюджет и не выполнять native close сам. Проверить также deferred cleanup
Stub после error-return. Полный error-path teardown не должен зависеть от
удачного планирования goroutine.

## P2-1 — warm-forget остаётся O(E²), включая самый обычный неизменный список

**Evidence.** `internal/policy/profile/forget.go:24` создаёт новый resolver
для каждого ранее записанного entry (`:30`). stillNamed (`:285`) каждый раз
строит новый presence map и перебирает current с начала. Проверка одинакового
spelling срабатывает внутри этого цикла: для entry номер i все предыдущие i
пути уже разрешены. `copy.go:303` аналогично создаёт resolver заново для каждого
недоступного source; recordVouches (`:350`) снова индексирует весь recorded.

Одноразовый счётчиковый probe вызвал настоящий forget на крошечном дереве
обычных файлов по одному байту, `previously == current`, без respelling,
копирования, изменения правил или удаления. Он удерживал созданные существующим
hook resolver и считал их места/снимки:

| Entries | Создано resolver | Разрешено places | Всего children в прочитанных snapshots |
| ---: | ---: | ---: | ---: |
| 4 | 4 | 6 | 12 |
| 8 | 8 | 28 | 56 |

Это E(E−1)/2 place resolutions и E(E−1) перечисленных children. В новом
TestAWarmCopyPaysResolverWorkOncePerEntryNotOncePerPair считаются только
вызовы Open/ReadDir; один ReadDir(-1) читает B children и создаёт byName map
размера B (`fold.go:306`). Когда B растёт вместе с E, O(E) вызовов ReadDir
не означает O(E) выполненной работы или объёма аллокаций.

Дополнительно alias branch (`fold.go:363`) сканирует все snap.children на
каждый новый alias, хотя canonical sibling values уже кэшированы. Этот кэш
уменьшает opens, но не делает сравнения всех разных alias линейными.

**Impact / confidence.** Высокая уверенность; квадратичная форма измерена на
4/8 entries без искусственной нагрузки. Warm startup продолжает создавать
повторные directory snapshots/maps даже при неизменных правилах. Масштаб
задержки на большом живом профиле здесь не измерен, ускорение в процентах
не обещается. `9a1cb8a` полезен, но весь пункт раунда 2 им не закрыт.

**Recommendation.** Сначала один exact-cleaned-spelling set для current —
он сразу делает обычный unchanged-forget линейным без filesystem comparison.
Resolver и canonical-presence index переиспользовать на протяжении участка,
на котором нет мутаций, инвалидировать после реального clear/mirror, а не
после каждого вопроса. Для alias добавить обратный индекс canonical path →
единственный stored name с явным состоянием неоднозначности. Сохранить
различение Unicode names, hard-link directory entries, отсутствующих копий
и reserved names. Между отдельными запусками такие ответы не кэшировать.

**Tests.** Считать не только число ReadDir, но и суммарное число перечисленных
entries, resolutions и аллокации; маленькие E/2E fixtures достаточно. Сравнить
совпадающие spellings, respelling, missing source и clear между двумя вопросами.
Временный probe удалён после измерения; существующие шесть адресных profile
тестов PASS, включая Unicode/alias-aware resolver и hard-link refusals.

## P2-2 — частично неизвестный conhost probe всё ещё может дать PASS

**Evidence.** `internal/e2e/conhost_test.go:258`, prowlMeasureHost: неожиданные
ошибки OpenThread записываются в notes (`:393`, `:406`), но не делают результат
unmeasured, если хотя бы один другой поток проверен. На `:409` examined > 0
заканчивает retry; на `:440` и `:441` measured/unmeasured определяются только
нулём examined. Пример: первый живой поток отказал в обоих правах, второй
вернул неизвестную ошибку — host получает measured=true, unmeasured=false,
open=[], и весь probe может завершиться кодом 0.

Аналогичная проблема у process doors: отдельная неизвестная ошибка остаётся
notes, если остальные двери ответили, а ошибка OpenProcessToken после удачного
OpenProcess вообще не классифицируется (`:293`). Улучшение «все thread IDs»
реально, но «попробовали все» ещё не означает «все определённо закрыты».

**Impact / confidence.** P2, высокая уверенность по oracle. Это пробел
регрессионного доказательства, не измеренный обход production DACL. Простой
сбой измерителя по одному объекту может скрыться за успехом остальных.

**Recommendation.** Хранить неопределённость по каждой обязательной двери.
Неизвестная ошибка по живому объекту должна давать отдельный nonzero exit,
даже если другие потоки проверены. Исчезновение объекта нужно подтвердить
повторным перечислением, как уже делается для исчезнувшего host; не приравнивать
его к закрытой двери. Различать QUERY-process failure и TOKEN-open failure.

**Tests.** Инъекционный oracle: два живых thread IDs, один определённо denied,
второй с неожиданной ошибкой — результат unmeasured, не PASS. Аналогично для
одной неизвестной process/token двери. Сохранить положительные контроли,
когда доступ действительно был до Shield, и born-before/between/after тест.

## P2-3 — новый shield-thread тест обходит политику скрытых subprocess

**Evidence.** Новый `internal/win/proc/shield_threads_test.go:385` запускает
spawner через обычный os/exec.Command без SysProcAttr и без quietexec.
Тест не берёт hidden console harness; два probe запускаются через proc.Run,
который намеренно наследует консоль родителя. `TestMain` в middle_test.go
не прикрепляет такую консоль для обычного m.Run.

Если test binary запущен GUI/IDE/background runner без attached console,
console-subsystem spawner может получить видимое окно. Перенаправление Stderr
в bytes.Buffer не задаёт CREATE_NO_WINDOW. Предыдущие тесты этого пакета
могут случайно оставить hidden console, поэтому полный suite и адресный
запуск данного теста способны вести себя по-разному. Это другой путь, чем
own-console opt-in, исправленный `ab26360`.

**Impact / confidence.** P2: возврат мешающих пользователю окон/фокуса в
неинтерактивном запуске тестов. Структура запуска и отсутствие ограничивающих
флагов подтверждены; видимое окно намеренно не создавалось. Условия создания
консоли описаны в [Process Creation Flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags).

**Recommendation.** Spawner запускать через существующий quietexec.Command.
Для прямых proc.Run обеспечить hidden-console harness у теста, если ему
нужна реальная общая консоль; не добавлять CREATE_NO_WINDOW в production Run,
где это меняет семантику Ctrl+C. Проверить адресный запуск из detached runner,
а не только случайный порядок всего пакета.

**Tests.** Наблюдение отсутствия видимого console window у harness и его
детей с одновременным подтверждением работы thread-probe. В этом ревью
потенциально показывающий окно тест не запускался.

## P3-1 — первый ACL preflight выделяет полный heldEntry slice и сразу выбрасывает его

**Evidence.** `sweep.go:357` отбрасывает результат readable, кроме owner/error.
Однако `readable` вызывает entriesOf, а `entries.go:97` выделяет
`make([]heldEntry, 0, dacl.count)`. Это O(A) дополнительной Go памяти и работы
на объект с A ACE поверх уже выделенного Windows descriptor. Следующий
classify pass снова читает/разбирает этот ACL. Compiler escape analysis
подтверждает выход slice на heap; это не предположение о результате inlining.

**Impact / confidence.** P3, высокая уверенность. Суммарно preflight производит
O(Σ Aᵢ) ненужного allocation traffic на большом дереве; одновременно удерживаемая
память ограничена workers, но общий объём работы/GC этим не устраняется.

**Recommendation.** Объединить исправление с P1-1: validation walk по ACE без
сохранения их в slice плюс вычисление owned bool внутри времени жизни descriptor.
Точно сохранить отказ на неподдерживаемом ACE type и на GetAce failure.
Не сливать read-only preflight с первым ACL write: отказ до изменения дерева
остаётся отдельной гарантией. Многоступенчатый grant произвольного дерева не
становится O(1) от отказа от одной allocation.

**Tests.** Существующий unsupported-ACE preflight должен по-прежнему отказывать
до publish. Маленький allocation test может показать отсутствие heldEntry
slice в validation-only пути, не задавая жёсткого общего числа allocations
WinAPI wrappers. Учитывать native allocations отдельно от Go heap.

## P3-2 — lifetime SID уже ограничен в audit/Prune, но не в остальных ACL операциях

**Evidence.** `sid.Parse` выделяет SID через ConvertStringSidToSidW, освобождение
теперь явно доступно через sid.Free. Успешные Set/Deny/Remove (`set.go:68`,
`:177`, `:188`) не возвращают SID после apply. Isolate (`isolate.go:60`) и
TakeBack (`reclaim.go:42`) также держат свои parsed SID до конца процесса.
sandboxIdentities (`owner.go:138`) добавляет member SID в глобальный pinned
slice (`:192`), а не в lifetime конкретной операции. fromNothing
(`isolate.go:232`) выделяет ещё три SID при каждом встреченном NULL DACL.

**Impact / confidence.** P3, высокая уверенность по ownership. Для короткого CLI
с несколькими грантами цена небольшая и процесс возвращает память при выходе.
Для большого списка грантов, множества NULL-DACL объектов или повторных вызовов
в одном процессе native heap растёт с числом операций; Go allocs это не покажут.
Исправленные WritablePass/StripOwnPass не имеют этого конкретного дефекта.

**Recommendation.** В распространённых коротких функциях — defer sid.Free
после успешного Parse. Для Isolate/TakeBack — operation context, как уже сделано
для StripOwnPass, со всеми parsed SID и Go-owned member buffers. Освобождать
его только после завершения workers и последнего SetEntriesInAcl/EqualSid.
fromNothing может использовать SID этого же контекста. Смена ownership без
такого срока жизни способна повторить P1-1, поэтому не раздавать Free вслепую.

**Tests.** Проверять баланс sid.Parses/sid.Frees после одной успешной операции
и её error path; отдельно подтвердить отсутствие роста global pin при повторных
операциях. Достаточно нескольких объектов и повторов, нагрузочный тест не нужен.

## Стоимость и безопасный порядок оптимизации

Сначала P1-1 и P1-2, затем P2-2 как полнота security oracle. После этого P2-1
даёт наиболее ясное уменьшение O и allocation traffic без смены механизма.
P3-1 естественно входит в исправление lifetime ACL; P3-2 переносит уже имеющийся
успешный шаблон operation context на соседние вызовы.

Для первого grant неизвестного существующего дерева остаётся нижняя граница
Ω(N): любой непрочитанный объект может иметь внешний hard link, собственный
ACL или sandbox owner. Исключать target/node_modules из проверки нельзя.
Для warm profile вопросов цель — O(E + прочитанные directory entries) на
неизменяемый участок, а не E новых индексов над одним набором. Между clear/mirror
нужна явная инвалидизация, между CLI runs — новая проверка реального дерева.

Параметр window ограничивает pipeline, но не всё дерево: snapshot sandbox-owned
entries остаётся O(S), S ≤ N; WalkDir/ReadDir(-1) держит списки детей каталогов.
При оценке ACL write учитывать и работу Windows по наследованию:
[SetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
сам распространяет inheritable ACE на существующих детей. Число Go apply calls
не равно числу filesystem objects, которые Windows затронет. Повторные native
обходы — кандидат для будущего измерения на маленьком вложенном fixture, не
доказанное здесь отдельное P-нарушение. Переставлять parent-before-child writes
или ослаблять preflight ради него без нового boundary oracle нельзя.

256-element buffers в pathid действительно заменили прежние безусловные 64 KiB,
хотя compiler всё ещё отправляет их на heap из-за формы syscall seam. Это
существенно меньшая allocation, не нулевая. Общий mutable scratch buffer или
межоперационный path cache ради исчезновения этой allocation не оправданы:
ошибка ownership/identity стоит больше сохранённых сотен байт.

## Проверки и условия приёмки

На Go `1.26.0 windows/amd64` выполнены **22 существующих адресных теста:
22 PASS, 0 SKIP**, плюс один временный measurement test с двумя подслучаями.

| Набор | Что проверено | Результат |
| --- | --- | --- |
| internal/sandbox/exec | Три pump/drain tests; controlled resize-before-close; controlled hung close; три birth-list guard cases | 8 PASS |
| internal/win/acl | Owned/unowned snapshot; revoke snapshot; fail-closed fallback; WritablePass и единичный SID lifetime | 6 PASS |
| internal/policy/profile | Три hard-link copy cases; DedupeEntries; warm-copy resolver; alias cache | 6 PASS |
| internal/win/pathid | Grant и copy отказывают при ошибке enumeration после первого имени | 2 PASS |
| Временный profile probe | Настоящий unchanged forget, 4/8 files, resolver/snapshot counters | PASS; числа в P2-1; файл удалён |
| Compiler escape analysis | `go build -gcflags=-m=2` для acl/profile/pathid | Успех; heldEntry/map/UTF-16 heap allocations подтверждены |

Эти PASS не закрывают обнаруженные пункты: lifetime freed native pointer,
drain-first scheduling и частично неизвестный conhost oracle существующими
положительными сценариями не измеряются. Full suite, race suite, live console
hang, настоящие sandbox accounts и own-console leg здесь не запускались.

Read-only запрос CI по **eeab4d6** не нашёл workflow run. На момент проверки
последний завершённый зелёный `tests` —
[35631016860](https://github.com/PHPCraftdream/wuserbox/actions/runs/35631016860)
на **4fd109a**. Параллельно шёл
[35688799013](https://github.com/PHPCraftdream/wuserbox/actions/runs/35688799013)
на другом SHA **9df0833**; его результат не подменяет приёмку этого среза.
Ревью не запускало новый CI, не делало push и не обновляло свой базовый HEAD
вслед за чужими коммитами.

В workflows сохранены no-skip/name-count проверки boundary, отдельный own-console
opt-in и одинаковый go-version-file для test/release. GoReleaser запускает
обычный suite перед публикацией, но сама публикация не должна считаться
заменой обязательных именованных проверок CI на выпускаемом SHA.

Для релиза нужны исправления обоих P1, адресные negative controls из их описаний,
исправленный частичный oracle P2-2 и зелёный обязательный account/console/lease/
filesystem boundary на финальном SHA. Для эксплуатации доверенных CLI остаётся
полезная дополнительная файловая защита с опубликованными ограничениями, но
рекомендацию выпускать этот срез как готовую песочницу для враждебного кода
данный раунд не даёт.

Общедоступные Everyone/Users writable directories, доступное чтение, сеть,
clipboard/desktop и уже открытые file handles остаются документированными
границами модели. Их не считать новыми находками; и наоборот, не прикрывать
ими native use-after-free в привилегированном ACL-коде или зависание teardown.
