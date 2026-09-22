# Security and performance review — 2026-09-27 — round 7 — P0–P3

## Вердикт и проверенный срез

**Нового подтверждённого P0 не найдено. Релиз пока не рекомендую: исправление
SID lifetime ввело другую ошибку передачи указателя в Windows — P1-1.
Дополнительно подтверждены три P2; остаются две возможности оптимизации P3.**

Открыто: **P0 — 0; P1 — 1; P2 — 3; P3 — 2.** Это результат ограниченного
ревью, а не доказательство отсутствия других уязвимостей. P1 установлен
по коду, escape/liveness analysis и машинному коду; падение или побег этим
путём не воспроизводились. Два P2 измерены обычными файловыми операциями
на временных объектах; третий — чистым вызовом функции обработки пути.

Проверен **`94f0225b37e93ed6da044550425a34e2bbc46c49`**. Последняя календарная
неделя относительно даты HEAD — **16–22 сентября 2026 включительно**:
234 коммита с merge-коммитами, 222 без них. Дата имени этого файла обозначает
номер раунда; в проверенной истории нет коммитов за 27 сентября. Рассмотрены
история изменений по подсистемам, предыдущие шесть отчётов, семь исправляющих
коммитов после [раунда 6](security-performance-review-2026-09-26-round6.md)
и текущая реализация основных границ. Каждый промежуточный SHA отдельно
не собирался. Номера строк ниже относятся к проверенному HEAD.

Локально: **30 существующих адресных top-level tests PASS, 0 SKIP**,
три небольших measurement-теста PASS и компиляция пакета SID с `-live`,
`-m=2`, `-S`. Тулчейн — `go1.26.0 windows/amd64`. Measurement-тесты записывали
наблюдаемое поведение, а не утверждали, что обнаруженный дефект исправлен;
их временные файлы удалены. Production-код и существующие тесты не менялись.
Не запускались полный suite, benchmarks, UAC, реальные account-chain
и административные прогоны. Пользовательские проекты не затрагивались,
видимые окна и эксплуатационные программы не запускались.

**CI этого SHA не подтверждён.** Запрос `gh run list --commit <полный SHA>`
завершился ошибкой соединения с `api.github.com`. Это не результат тестов
и не доказательство повторения billing failure из раунда 6. Старый зелёный
CI к этому срезу не приписывается.

## Что стало с находками раунда 6

| Прежний пункт | Результат на HEAD |
| --- | --- |
| P1: Go-owned SID терял владельца памяти | `4eacc19` удерживает `owner`, передаёт typed pointer в `format`, сохраняет ошибку `CurrentUser`. Compiler подтверждает `buf.ptr` live при вызове `format` и `owner` live при native adapter call. Однако введённый interface лишает другой адрес syscall-обработки компилятора: новый P1-1 ниже. |
| P2: locked stale copy забывалась | `51993b6` различает отсутствие и ошибку в обеих ветвях `clearEntry` и в подготовке destination directory. Четыре адресных tests Copy/Clear/retry PASS. Другой пропуск ошибки остался в cleanup-glob walk: P2-1. |
| P2: SandboxGroup терял контракт при member lookup | `3c7d097` переносит различие SandboxGroup/IdentifierAlone на `errNoSuchGroup`; production-ветвь отказывает до изменений. Четыре адресных теста member-stage PASS. |
| P2: HomeTop reapply переносил родительские flags без адаптации | `f22dc51` учитывает тип объекта и поколение. Таблица flags и обычный lifecycle-тест повторной выдачи PASS: созданный файл остаётся writable, следующий уровень не получает Modify, owner cap сохраняется. Регрессия корня диска рассмотрена в P2-3. |
| P2: второй оператор автоматически пересоздавал чужую учётку | `35d8ad3` требует owner SID из account comment до удаления. Unit-тесты foreign/unknown/error/self branches и формата comment PASS. Настоящее создание двух операторов/учёток в этом ревью не выполнялось. Машинные ресурсы и пользовательские lock namespaces остаются явно описанным ограничением. |
| P3: partial-forget пересоздавал resolver и весь keep-index | `2994b27` сохраняет resolver и resolutions оставшихся entries. Эта часть улучшена; полная сложность всё ещё квадратична по directory children и обходам cache maps, P3-1. |
| P3: warm preparation попарно разрешал grant paths | `a5fbe57` добавляет operation-local index. Три теста warm lookup, изменения списка и alternate spelling PASS. В неизменном проходе путь разрешается один раз на recorded/asked spelling, вместо одного раза на каждую пару. |

## P1-1 — interface syscall seam оставляет выходной указатель SID на подвижном Go-стеке

**Статус:** регрессия `4eacc19`. **Confidence:** высокая для нарушения
контракта указателей; частота проявления и эксплуатационная пригодность
не измерялись. **Приоритет:** исправить до релиза.

**Evidence.** `internal/win/sid/sid.go:17,26–28` теперь хранит процедуру в
`textConverter`, чей метод принимает `...uintptr`. В `format`, `:127–130`,
адрес локальной переменной `text` преобразуется в `uintptr` и передаётся
через этот interface call. Это обычный косвенный Go-вызов. Специальная
обработка `//go:uintptrescapes` конкретного `(*syscall.LazyProc).Call`
не переносится на объявление метода интерфейса.

На объявленном проектом Go 1.26.0 получено:

```text
sid.go:128:6: stack object text *uint16
sid.go:129:49: live at indirect call: ... owner text ...
sid.go:127:13: pointer does not escape
sid.go:127:37: owner does not escape
```

В `-S` это действительно адрес `text+80(SP)`, помещённый во второй элемент
`[2]uintptr` перед `CALL DX`; это не предположение по отсутствующему
`KeepAlive`. Сам массив аргументов выделяется на heap, но его числовой
элемент не становится отслеживаемым указателем на stack slot.

`KeepAlive(owner)` сохраняет достижимость входного storage. Он не закрепляет
адрес выходной переменной `text` и не исправляет число при перемещении стека
в вызываемом Go-коде. Тогда Windows получает старый адрес для записи
возвращаемого указателя; текущая копия `text` может остаться пустой, а запись
попасть в прежнее расположение stack slot. У stack-backed `sid.Value`
тот же нетипизированный переход затрагивает и входной адрес.

Контракт подтверждают [документация compiler directives](https://pkg.go.dev/cmd/compile#hdr-Compiler_Directives),
[конкретный syscall wrapper](https://go.dev/src/syscall/dll_windows.go)
и [правила unsafe.Pointer](https://pkg.go.dev/unsafe#Pointer).
Для текущего бинарного результата основное доказательство — вывод его
собственного компилятора, а не версия документации сайта.

**Impact.** Возможны неверная identity, отказ преобразования, native fault
или повреждение памяти в центральном helper, используемом в том числе
elevated setup. Оснований объявлять из этого управляемый sandbox escape
нет. Обычные форматирующие тесты проходят, потому что они не доказывают
неподвижность адреса на всех границах Go/native.

**Recommendation.** Сделать seam типизированным: передавать `unsafe.Pointer`
и `**uint16` либо возвращать native result из typed adapter. Преобразование
в `uintptr` оставить непосредственно в вызове конкретного `LazyProc.Call`
внутри adapter. Сохранить `KeepAlive` владельца SID и существующее
распространение ошибок. Добавление одного `KeepAlive(&text)` к нынешнему
interface call не является достаточным исправлением перемещения стека.

**Tests.** Сохранить три новых formatter/error tests и проверить `-m=2`/`-S`
после изменения: адрес не должен пересекать обычную Go-границу как число,
указывающее на подвижный stack slot. В этом ревью принудительное перемещение
стека, fault injection в native memory и нагрузочный прогон не выполнялись.

## P2-1 — cleanup glob молча пропускает закрытый каталог-предок

**Статус:** другая ветвь прежнего класса ошибок cleanup; исправленный
`clearEntry` здесь не вызывается. **Confidence:** высокая, измерено через
public `Copy` на временном профиле.

**Evidence.** `internal/policy/profile/cleanup.go:135–137` вызывает
`lookAt(root, childPath)` и на любой отказ продолжает обход следующего
ребёнка. `mirror.go:224–226` сворачивает все ошибки `Lstat` в `false`.
Поэтому sharing violation у каталога-предка читается как основание вообще
не искать подходящие cleanup names под ним.

Маленький тест использовал правило `app/cache.txt`, существующий временный
файл и обычный exclusive handle на временный `app`. Результат:

```text
Lstat(app): sharing violation
Copy: error=nil
app/cache.txt после Copy: существует
тот же Copy после освобождения handle: файл удалён
```

Контрольная повторная операция показывает, что glob корректен и файл
действительно входил в область очистки. При этом предыдущий record и
profile-copy список были пустыми: ответ получен именно от cleanup-glob
walk, а не от пропуска в `forget`.

**Impact.** Запуск может продолжиться с состоянием, которое cleanup должен
был убрать, и без сообщения о неполном результате. Это ошибка очистки
профиля, не запись за его пределы. В отличие от закрытого round-6 случая,
само правило cleanup сохраняется, поэтому следующий запуск может повторить
очистку; утверждать, что файл забывается навсегда, было бы неверно.

**Recommendation.** До обхода поддерева различать `IsNotExist` и невозможность
его проверить. Для предка, под которым mask может совпасть, второе должно
остановить `Copy` с исходной ошибкой. Для явно нерелевантной ветви сначала
применять `mayMatchDescendant`, чтобы чужой закрытый каталог не блокировал
несвязанную очистку.

**Tests.** Public Copy с закрытым релевантным предком должен отказать;
после закрытия handle повторная операция должна убрать совпадение.
Отдельно нужны отсутствующий предок и закрытое нерелевантное поддерево.

## P2-2 — audit вычитает поздний deny из уже выданного explicit allow

**Статус:** новая находка прежнего кода; исправление inherit-only не
опровергается. **Confidence:** высокая, сверено с обычной файловой операцией.

**Evidence.** `internal/win/acl/entries.go:279–299` собирает все allow и deny
в две маски и возвращает `granted &^ refused != 0`. Порядок ACE потерян.
`WritablePass.Writable`, `:393–406`, использует именно этот ответ для audit.

Проверен временный каталог с explicit allow для Everyone и расположенным
после него inherited deny для того же SID. Такая последовательность
совместима с порядком explicit ACE перед inherited ACE. Измерено:

```text
WritablePass: everyone=false, users=false, error=nil
обычное создание файла внутри: error=nil
```

Здесь write объясняет allow для Everyone; ownership сам по себе не даёт
право создавать файлы. Windows учитывает ACE последовательно и может
завершить проверку разрешением до позднего deny. См.
[правила AccessCheck](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object).

**Impact.** `--audit` пропускает часть общедоступных writable-каталогов —
именно тех исключений из файловой границы, для поиска которых он нужен.
Это ложное отрицание диагностики; текущая реализация sandbox enforcement
от audit не зависит, и новый escape этим измерением не доказан.

**Recommendation.** Сохранить порядок разрешения отдельных requested bits
либо использовать подходящую native access-evaluation модель. Раннее
разрешение нельзя задним числом отменять поздним deny. Сохранить проверки
inherit-only, partial deny, null DACL и явный unknown-result. Не обещать
полную эквивалентность реальному токену простой суммой прав отдельных групп.

**Tests.** Закрепить explicit allow перед inherited deny и обратный порядок
с deny до allow; сравнивать с native результатом на временном объекте.
Два inherit-only regression tests не покрывают этот случай.

## P2-3 — новый расчёт поколения отвергает потомка корня диска

**Статус:** регрессия `f22dc51`. **Confidence:** высокая для helper и
production call path; реальная выдача целого тома не выполнялась.

**Evidence.** `internal/win/acl/sweep.go:602–607` отрезает `root` как строковый
префикс и требует, чтобы остаток начинался с разделителя. У корня диска
разделитель уже входит в сам root. Чистый вызов на вымышленных строках дал:

```text
root="Q:\", path="Q:\child.txt": error="... is not below ..."
root="Q:\dir", path="Q:\dir\child.txt": generations=1, error=nil
```

К этому пути приходят `handDown`, `:524–542`, из классификации и записи
sandbox-owned потомков. Нормализация CLI сохраняет завершающий разделитель
корня диска; отдельного запрета таких grant roots нет. Для grant с
наследуемыми записями и owned потомком валидный path поэтому останавливает
выдачу или повторный init.

**Impact.** Часть допустимых grant/reapply операций ломается на volume root.
Отказ не расширяет права. Предшествующие сужающие операции обхода могут уже
успеть выполниться — обещать полный rollback здесь также нельзя.

**Recommendation.** Учитывать already-terminated root при выделении
относительного хвоста; сохранить точное сравнение spellings одного обхода.
Не заменять его слепо Unicode `EqualFold`/`filepath.Rel`, поскольку
filesystem-distinct names проект уже специально различает.

**Tests.** Чистая таблица root/child: drive root, обычный directory root,
UNC share root, deeper child, соседний prefix и сам root. Для неё не нужны
доступ к настоящему диску, ACL sweep или UAC.

## P3-1 — partial-forget остаётся квадратичным по полной работе

**Статус:** частично устранённый P3 раунда 6; не регрессия unchanged warm-copy.
**Confidence:** высокая, формула зафиксирована проходящими тестами HEAD.

**Evidence.** `forget.go:125–150` сохраняет stretch через scoped retract.
Однако `fold.go:546–569` на каждом реальном удалении перебирает maps целиком
и удаляет snapshot родителя. Следующий ещё не разрешённый stale sibling
заново вызывает `snapshot`, `:350–380`, с `ReadDir(-1)` и построением `byName`.

Текущий `TestAForgetThatTakesHalfTheRecordBackRetractsItsAnswersNotRebuilds`
прошёл с заложенными в него счётчиками:

| Исходных entries E | Resolver instances | Resolutions | Directory reads | Обработано children |
| --- | --- | --- | --- | --- |
| 4 | 1 | 6 | 3 | 9 |
| 8 | 1 | 12 | 5 | 30 |

Resolutions теперь линейны. Но сумма children равна
`E + (E-1) + ... + E/2 = 3E²/8 + 3E/4`. Это прямо считается в
`partial_test.go:96–106`. Дополнительно каждый retract пересматривает
сохраняемые resolutions/aliases; folding имён и новые directory maps
увеличивают allocation traffic. Один resolver не означает линейную
стоимость всего прохода.

**Impact.** Улучшение warm path реально, но частичная массовая очистка
большого списка по-прежнему дорожает квадратично. Для небольшого default
списка это не релизный блокер. Время на больших наборах не измерялось;
цифры ускорения не заявляются.

**Recommendation.** Уменьшить цену invalidation: reverse index по canonical
place/parent вместо полного map scan, а для точно известных удалений —
обновление соответствующего snapshot либо предварительное планирование
набора удалений с повторной проверкой затронутых identities перед действием.
Не оставлять stale snapshot просто ради меньшего счётчика. Alias retry,
Unicode semantics, частично сохранённые деревья и failure paths должны
сохранить текущий контракт.

**Tests.** Продолжить считать не только resolutions, но и children, map
visits и allocations на маленьких 4/8 fixtures. Существующий тест сейчас
принимает квадратичную сумму как ожидаемый результат, поэтому его PASS не
закрывает исходный вопрос о снижении O всей операции.

## P3-2 — revoke повторно разрешает одни и те же trustee SID на каждом объекте

**Статус:** оставшаяся возможность оптимизации; упоминалась в рекомендациях
раунда 6 и не изменена семью последними исправлениями. **Confidence:** высокая
для структуры вызовов; выигрыш по времени не измерялся.

**Evidence.** `internal/win/acl/reclaim.go:201–243` вызывает `sandboxGroup`
для подходящих changing ACE, а тот каждый раз вызывает `sid.Name`.
`internal/win/sid/sid.go:91–115` делает sizing lookup, выделяет name/domain
буферы и выполняет второй lookup. Operation-owned `identities` уже устраняет
повторный member lookup, но не это распознавание повторяющегося trustee.

При N объектах и A подходящих ACE на каждом получается O(N·A) account-name
lookups, даже если различных trustee SID всего U. Пропустить обход самих
ACL нельзя, но эту часть native-вызовов и временных буферов можно сократить
до O(U) на операцию. Это не новая утечка native SID: прежнее scoped Free
в token/account/ACL helpers сохранено.

**Recommendation.** Operation-local memo результата классификации,
ключ — значение SID, а не его адрес внутри descriptor. Адреса перестают
быть действительными после Free и переиспользуются. Ошибки разрешения
должны сохранить нынешний консервативный смысл, а memo закончиться вместе
с операцией. Отдельная небольшая возможность для audit — обход ACE без
полного `[]heldEntry`, когда потребителю нужны только два ответа, но сначала
нужно исправить P2-2 и сохранить обработку неизвестных ACE.

**Tests.** Небольшое дерево с повторяющимися trustee и счётчиком native
name lookups; отдельно read error, неизвестный SID и конец операции.
Считать Go allocations и native allocations раздельно. Большой benchmark
для доказательства этой структуры вызовов не нужен.

## Остальные границы и пределы проверки

Прослежены account → stub → fully restricted token, process/thread/default
DACL и conhost shields, lease handoff, suspended launch/job assignment,
stdio/relay teardown/resize, ACL isolation/revoke/Prune, path identity,
hard-link preflight, profile copy и bounded transfer, state/config,
check/audit, CI и release workflows.

- Ранее найденный descriptor-owner UAF по прежнему пути не повторяется:
  решение принимается до Free, identities держат member buffers до End.
  Новый P1-1 относится к другому storage и другой Go/native-границе.
- Relay close ownership забирается синхронно до worker; resize регистрируется
  под mutex; close ждёт уже начатые resizes, а finish deadline не ждёт
  синхронного `ClosePseudoConsole`. Семь console-free тестов ordering,
  pipes-only cleanup и birth enumeration guard PASS. Реальные permissions
  всех hosts/threads этим набором не проверены.
- Job присваивается suspended child до resume; lease удерживается до
  profile fill и передаётся stub как non-inheritable handle. Нового
  подтверждённого нарушения этих порядков статическое чтение не выявило.
- Проверки hard-link enumeration различают EOF и ошибку; выдача проходит
  preflight до ACL publish. Profile copy ограничивает количество реально
  переносимых bytes и использует `os.Root`; старые full-profile copying
  defaults не вернулись. Эти свойства не означают атомарную транзакцию
  со всеми внешними изменениями файловой системы.
- `--check` спрашивает токен запускаемой учётки, а при совпадении текущего
  SID — её текущий токен. Audit не участвует в enforcement, но его ложное
  отрицание P2-2 важно для оценки документированного остаточного доступа.
- CI и release читают версию Go из `go.mod`. Release hook действительно
  содержит `go test ./...`; отдельные no-SKIP boundary/hive/own-console gates
  этим hook не заменяются. Их прохождение для текущего SHA не установлено.

Общие Everyone/Users-writable директории, сеть, shared desktop и
межоператорные lock namespaces остаются ограничениями из `docs/limits.md`.
Снижение прав относительно обычного запуска полезно, но не превращает
этот продукт в полную изоляцию произвольного враждебного кода от всей машины.

## Выполненные проверки

| Область | Результат |
| --- | --- |
| SID formatter: реальный Value.String, отказ formatter, ошибка CurrentUser | 3 top-level PASS, 0 SKIP |
| Profile: locked Copy/Clear/retry, scoped partial-forget, aliases/retract | 7 top-level PASS, 0 SKIP |
| ACL: group member-stage refusal, standalone control, HomeTop adaptation/lifecycle, allocation-free preflight | 7 top-level PASS, 0 SKIP |
| State: warm index, invalidation при изменении records, alternate spelling | 3 top-level PASS, 0 SKIP |
| Account ownership: классификация/отказ/свой recovery через seam, comment split | 3 top-level PASS, 0 SKIP |
| Relay/birth guard: только console-free fake-native ordering/error tests | 7 top-level PASS, 0 SKIP |
| Временные измерения cleanup, audit order, drive-root arithmetic | 3 PASS; их файлы удалены |
| SID compiler: `go build -gcflags='-live'`, `-m=2`, `-S` | Все exit 0; P1-1 установлен по compiler output |
| Exact-SHA CI | Не получен: ошибка соединения с GitHub API |

Ни один запущенный тест не упал. Полный suite, полный lint/vet,
административные account lifecycle, host/thread boundary и нагрузочные
измерения в этом раунде не запускались.

## Порядок перед выпуском

1. Устранить P1-1 через typed native adapter и перепроверить compiler output.
2. Исправить три P2 с небольшими адресными regressions; особенно cleanup
   должен отличать «не найдено» от «не удалось проверить», а audit — порядок ACE.
3. Получить зелёный CI итогового SHA с обязательными account/boundary,
   seeded-hive и opt-in own-console проверками. Включить новые критичные
   lifecycle regressions в явные gates, где пропуск не считается успехом.
4. Затем оптимизировать P3 отдельно. Без изменения модели проверки ACL
   первичная выдача большого существующего дерева остаётся как минимум O(N)
   по числу проверяемых объектов; обещать её O(1) нельзя. На unchanged warm
   пути уже есть полезные сокращения работы, которые надо сохранить.
