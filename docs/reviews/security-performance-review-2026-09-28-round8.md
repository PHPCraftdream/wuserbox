# Security and performance review — round 8 — P0–P3

## Вердикт и проверенный срез

**Новых подтверждённых P0/P1 не найдено. P1 раунда 7 с передачей SID через
небезопасный native adapter закрыт. Найдены две воспроизводимые P2 с потерей
данных при обслуживании профиля и три P3. Безусловную готовность к релизу
пока не подтверждаю: сначала устранить обе P2 и получить CI проверяемого SHA.**

Открыто: **P0 — 0; P1 — 0; P2 — 2; P3 — 3.** Отсутствие подтверждённого побега
в этом ревью не доказывает отсутствие остальных уязвимостей. Оба дефекта P2
касаются данных внутри профиля; запись за пределами файловой границы ими не
продемонстрирована. Для ограниченного повседневного использования с обычными
валидными правилами инструмент остаётся полезен, но эти дефекты не позволяют
обещать безопасную обработку ошибочных правил и старых записей копирования.

Проверен **`e67a380ffe40de68a4d88b154d45725cd7aec946`**. Последняя календарная
неделя относительно даты HEAD — **16–22 сентября 2026 включительно**: 248
коммитов с merge-коммитами, 230 без них. Дата в имени файла продолжает
последовательность прежних раундов; коммитов за 28 сентября в проверенной
истории нет. Рассмотрены история по подсистемам, предыдущие отчёты, изменения
после среза раунда 7 `94f0225` и текущая реализация основных границ.
Каждый промежуточный SHA отдельно не собирался.

Production-код не изменён. Адресные проверки выполнялись в отдельном worktree,
на временных объектах, без UAC и создания видимых консолей. Большие деревья,
нагрузочные прогоны, реальные пользовательские профили и реальные registry
hives не использовались. Номера строк ниже относятся к проверенному HEAD.

## P0 — подтверждённых новых находок нет

Прослежены account → stub → fully restricted token, lease до заполнения
профиля и передача в suspended stub, process/thread/default-DACL shields,
birth/own/ConPTY hosts, job assignment до resume, ACL/grant/revoke/Prune,
hard-link и path-identity checks. Нового доказанного способа получить
unrestricted execution или изменить защищённый внешний файл не установлено.

Реальный запуск атакующего процесса через новую учётку в этом раунде не
выполнялся. Console-free тесты teardown проверяют порядок и lifetime, но не
подменяют account/conhost/thread boundary-прогоны на административном runner.

## P1 — подтверждённых открытых находок нет

Round 7 P1-1 закрыт коммитом `4c552af`. В
`internal/win/sid/sid.go:43–50` typed adapter принимает `unsafe.Pointer` и
owner slice, а преобразования обоих адресов в `uintptr` стоят прямо в вызове
конкретного `LazyProc.Call`. Проверено через
`go build -gcflags='-m=2' ./internal/win/sid ./internal/win/acl` на Go 1.26.0:

```text
sid.go:43:32: leaking param: pointer
sid.go:44:6: moved to heap: text
sid.go:45:58: uintptr(...) (//go:uintptrescapes)
sid.go:45:90: uintptr(...) (//go:uintptrescapes)
```

Это устраняет именно ранее обнаруженную передачу адреса movable stack slot
как обычного числа через interface. `KeepAlive(owner)` остаётся после native
вызова. Три адресных SID-теста прошли. Старую находку не переношу в новый
отчёт только потому, что код всё ещё использует unsafe.

## P2-1 — промежуточный alias в старом copy-record обходит защиту UsrClass.dat

**Статус:** подтверждено тремя файловыми измерениями. **Confidence:** высокая.

**Evidence.** `internal/policy/profile/reserved.go:207–245` запускает
разрешение имени только если подозрителен последний компонент пути:
`leafSuspicious` отбрасывает всё до последнего `/`. Между тем Win32 может
нормализовать и промежуточный компонент. `withinRecorded`,
`copy.go:224–236`, намеренно принимает прежние написания, а
`forget.go:76–80, 195–226` доверяет ответу `reservedAtResolved` /
`reservedWithinResolved` перед удалением.

На временном профиле был создан обычный файл
`AppData/Local/Microsoft/Windows/UsrClass.dat` с контрольным содержимым.
Сначала каждый путь открывался через тот же `os.Root`, подтверждая, что он
действительно достигает объекта. Затем вызывался публичный `Clear` с одной
записью прежнего копирования:

| Запись в record | Результат Clear | Контрольный UsrClass.dat |
| --- | --- | --- |
| `AppData./Local/Microsoft/Windows/UsrClass.dat` | `nil` | удалён |
| `AppData/Local./Microsoft/Windows/UsrClass.dat` | `nil` | удалён |
| `AppData/Local/Microsoft./Windows` | `nil` | удалён вместе с каталогом |

**Impact.** Старый record с таким написанием может удалить class hive
песочницы и его окружение при `--no-ai` или исключении записи из правил.
Это потеря сохранённых настроек/состояния и нарушение явно заявленного
правила «registry файлы не принадлежат копировщику». Измерялось удаление
синтетического файла, а не последствия удаления загруженного registry hive:
открытый Windows handle иногда может отказать в удалении, и полагаться на
этот случайный отказ как на защиту нельзя.

Триггер ограничен: текущий `within` уже отказывает новым правилам с точками,
пробелами и short-name компонентами. Но record предшествующих версий читает
другая функция именно ради совместимости. Record хранится вне профиля;
способа заставить sandbox произвольно записать его этим дефектом не найдено.

**Recommendation.** Проверять подозрительность каждого компонента и разрешать
весь путь перед решением о reserved-файле/дереве. Не ужесточать чтение legacy
record простым отказом от всех таких записей: это оставит копии навсегда без
штатного пути очистки. Ошибку разрешения существующего подозрительного имени
отличать от отсутствия, не превращая неизвестный ответ в разрешение удалить.

**Tests.** Расширить
`TestATakeBackSparesTheHiveARecordSpelledTheWayTheVolumeReadsIt`: alias в
каждом предке, удаление самого файла и его каталога, `Clear` и `Copy` с
previously; контрольный нерезервный сосед должен удаляться. Существующий
тест покрывает подозрительный leaf, но не этот путь.

## P2-2 — отказ от невалидного profile path приходит после удаления прежних копий

**Статус:** подтверждено через публичный `Copy`. **Confidence:** высокая.

**Evidence.** `internal/policy/profile/copy.go:62–76` сначала выполняет
`refuseEntriesCopyRefuses`, затем cleanup и forget. Однако
`refusals.go:155–173` проверяет только конфликтующие дубликаты и отрицательные
depth. Проверка самих путей `within` выполняется в `copyEntries`,
`copy.go:299–302`, когда прежние записи уже могли быть удалены.

Измерение: успешно скопировать `agent/auth.json`, добавить в destination
`agent/local.txt`, затем заменить `profile:` одним невалидным entry и снова
вызвать `Copy` с предыдущим record:

```text
invalid="."            refused=true auth_missing=true local_work_missing=true
invalid="../outside"   refused=true auth_missing=true local_work_missing=true
invalid="auth.json."   refused=true auth_missing=true local_work_missing=true
```

Во всех трёх случаях ошибка правильная, но приходит после удаления
контрольной копии и локального файла. `config.Load` проверяет структуру
источника, а обычный `setup.Run` не вызывает полную `--config validate`;
это достижимая ветка исполнения, а не только прямой вызов внутреннего helper.
`setup.fillProfile` сохраняет прежний record при ошибке, но уже удалённые
байты этим не восстанавливает.

**Impact.** Опечатка в редактируемых CLI-правилах уничтожает содержимое старого
bare-entry до сообщения об отказе. Исходные credentials иногда можно
скопировать заново; добавленное внутри песочницы состояние может не иметь
источника для восстановления. Ранее исключённые масками данные остаются
защищены этими масками — измерение относится к bare-entry.

**Recommendation.** В существующем общем preflight проверять `within` для
всех новых `rules.Profile` до любой cleanup/forget/copy mutation. Это O(E)
строковая проверка без обхода дерева. Использовать её и в `Plan`. Проверки
record оставить отдельно: их допустимый синтаксис отличается намеренно.

**Tests.** Для всех отказов пути проверять не только `err != nil`, но и
неизменность предыдущей копии, локального файла и cleanup-кандидата.
Дополнительно: валидный первый entry + невалидный второй, чтобы preflight
проверял весь список до первого изменения. Нынешний
`TestCopyRefusesAnEntryNamingTheProfileRoot` передаёт `previously=nil`,
поэтому удаления старой копии не наблюдает.

## P3-1 — partial-forget с сохранёнными exclusions остаётся O(E²)

**Статус:** оставшаяся ветка после реального улучшения `193dfd6`.
**Confidence:** высокая для числа операций; wall-clock ускорение не измерялось.

**Evidence.** Когда clear удалил entry целиком, `fold.go:698–724` точечно
обновляет snapshot родителя. Когда excluded-файл оставил каталог стоять,
`fold.go:725–729` удаляет snapshot родителя целиком. Следующий ещё не
разрешённый sibling снова перечисляет весь родительский каталог.

Маленький fixture содержал E каталогов по два файла: удаляемый `auth.json`
и исключённый `keep.txt`. Половина entries удалена из списка, другая
половина сохранена под эквивалентным uppercase-написанием. Все `keep.txt`
сохранились. Счётчики текущего resolver показали:

| E | Resolvers | Directory reads | Resolutions | Enumerated children |
| --- | --- | --- | --- | --- |
| 4 | 1 | 3 | 6 | 12 |
| 8 | 1 | 5 | 12 | 40 |

Для этой формы `children = E × (E/2 + 1)`. Один resolver и линейное число
resolutions уже достигнуты; общая стоимость перечислений всё ещё квадратична.
Обычная полная очистка sibling entries теперь действительно линейна:
существующие 4/8 regressions `partial_test.go` прошли.

**Impact.** Профиль с большим пользовательским списком и exclusions снова
дорого очищается при массовом удалении entries. Для небольшого default
списка это не блокер безопасности.

**Recommendation.** Различать «имя entry исчезло», «каталог entry остался,
изменились его потомки» и «его состояние неизвестно». Во втором случае
snapshot родителя entry не изменился: инвалидировать затронутое поддерево,
сохраняя перечисление и identity незатронутых siblings. Не расширять reuse
на creation/replacement и неизвестный исход. Закрепить оба 4/8 сценария
счётчиками reads/children, а не одним количеством resolvers.

## P3-2 — reverse-index не отзывает cached resolutions листьев удалённого дерева

**Статус:** подтверждён дефект внутреннего cache-контракта; вредное действие
публичного API этим сценарием не подтверждено. **Confidence:** высокая для
stale-ответа, ограниченная для практического воздействия.

**Evidence.** `notePlace`, `fold.go:374–381`, записывает canonical leaf в
`placeAt`, но не в `dirChildren`. Последний индекс содержит только ключи
directory snapshots (`noteDir`, `:438–446`). `retract`, `:671–697`, обходит
этот граф и удаляет `placeAt[key]` только для посещённых узлов. Terminal file
не является directory snapshot и в обход не попадает.

Измерение: resolve `tree` и `tree/deep/leaf.txt`, удалить `tree`, вызвать
`retract("tree")`, снова спросить leaf. Результат:

```text
retained=("tree\\deep\\leaf.txt",true) fresh=("",false)
```

**Impact.** Resolver подтверждает место, которого больше нет, и удерживает
его spelling memo. Текущий production-потребитель retraction — `forget`,
который после clear не создаёт новые имена; этого измерения недостаточно,
чтобы заявить удаление чужого файла или выдачу прав. Поэтому это P3, а не
ещё один «побег через stale cache».

**Recommendation.** Включить terminal canonical places в subtree reverse
index либо хранить resolutions под содержащим их каталогом. Отзыв должен
посещать и directory snapshots, и terminal resolutions, оставаясь
пропорциональным числу действительно затронутых элементов. Тестировать
несколько глубин, leaf и directory entries, alias spellings и untouched
sibling; сравнивать результат с новым resolver после операции.

## P3-3 — memo revoke всё ещё выделяет native-call scratch на каждом hit

**Статус:** возможность оптимизации allocations после закрытия повторных
account-name lookups. **Confidence:** высокая по compiler output; выгода по
времени не измерялась.

**Evidence.** `internal/win/acl/reclaim.go:290–309` создаёт локальный
`copied [68]byte` и передаёт его адрес в `CopySid` при каждом `trusteeKey`.
`trusteeAnswers.sandboxGroup` вызывает это до map lookup даже на cache hit.
Compiler output: `reclaim.go:294:6: moved to heap: copied`; variadic call
arguments также отмечены escaping. Тест с названием
`TestARepeatAnswerAsksNothingAndAllocatesNothing` уже допускает allocation
cost самого key и сравнивает с ним, а не требует ноль.

**Impact.** Native name lookups снижены с O(N·A) до O(U), но Go allocation
traffic формирования ключа остаётся O(N·A). Это не утечка native SID:
descriptor освобождается, operation-owned SID возвращаются Windows.

**Recommendation.** Revoke выполняется одной горутиной: scratch для CopySid
может принадлежать `trusteeAnswers` и переиспользоваться, а map key оставаться
копией байтов. Это снимает повторное выделение массива, хотя само по себе
не обещает устранить все allocations syscall adapter. Альтернатива —
сохранить typed SID view из живого descriptor, но не возвращать небезопасное
преобразование сохранённого `uintptr` обратно в Go pointer. Отдельно измерять
Go allocations и `sid.Parses/Frees`; correctness решения важнее нуля в тесте.

## Закрытие прежних находок и остальные границы

| Область раунда 7 | Результат на текущем срезе |
| --- | --- |
| SID native adapter/lifetime | закрыто кодом, compiler output и тремя тестами |
| Cleanup ancestor read errors | закрыто; locked/retry, absent и irrelevant-branch тесты PASS |
| Audit explicit allow / inherited deny order | закрыто; три теста с настоящими ACL и файловыми операциями PASS |
| Drive/UNC-root generations | закрыто; таблица всех заявленных форм PASS |
| Whole-entry partial-forget | линейность исходного сценария подтверждена; ограниченная очистка отдельно в P3-1 |
| Revoke trustee-name lookups | operation-local memo присутствует; unknown trustee и lifecycle двух операций PASS |

Дополнительно проверены следующие свойства по текущему коду:

- Fully restricted token сохранён; `DELETE` не возвращён к старой
  write-restricted модели. Own account SID и read-group storage удерживаются
  до native вызовов. Group/member lookup failures в production identity
  context не превращаются в standalone success.
- Relay close сначала забирает ownership, потом запускает worker. Resize
  регистрируется под mutex, close ждёт начатые resizes внутри worker;
  deadline не ждёт синхронного ClosePseudoConsole. Deferred cleanup stub
  закрывает только pipe ends. Семь console-free ordering/error тестов PASS.
- Hard-link enumeration различает EOF и ошибки; copy проверяет links до
  truncation и использует os.Root. Рост источника ограничен фактически
  передаваемыми bytes, scratch разделяется файлами одной операции.
- Tree lock использует canonical root; preflight/revoke identities имеют
  operation lifetime. Ограничение нескольких операторов с разными lock
  namespaces остаётся документированным, а не закрытым этим ревью.
- Check использует token настоящей учётки; audit не участвует в enforcement
  и считает права названных trustees, а не полную комбинацию групп token.
- CI и release читают версию Go из go.mod. Release hook содержит общий
  `go test ./...`, однако не заменяет отдельные no-SKIP gates boundary,
  seeded-hive и own-console.

Начальная безопасная выдача существующего дерева по-прежнему требует как
минимум O(N) просмотра его объектов: нужно обнаружить внешние hard links,
неподдерживаемые ACE и права sandbox-owned файлов. Уменьшение лишних
перечислений, разрешений SID и allocations полезно; обещать O(1) bootstrap
без другой модели проверки оснований нет. Unchanged warm-copy и warm-grant
индексы уже дают реальные улучшения, их нельзя терять при исправлениях.

Пределы из `docs/limits.md` сохраняются: Everyone/Users-writable места,
неограниченная сеть, чтение доступных секретов, shared desktop/clipboard,
открытые до revoke handles. Это файловая защита с явно описанными
исключениями, а не полная изоляция произвольного враждебного кода от машины.

## Выполненные проверки и CI

| Проверка | Результат |
| --- | --- |
| SID formatter/native error paths | 3 top-level PASS |
| ACL: ACE order, members refusal/standalone, generations, revoke memo | 10 top-level PASS |
| Profile: cleanup locked ancestor/retry/irrelevant branch, whole-entry retraction | 6 top-level PASS |
| Relay/birth guard: только console-free ordering/error tests | 7 top-level PASS |
| Pathid: enumeration EOF/errors/growth, copy refusal before write | 5 top-level PASS |
| State: warm path index/invalidation/alternate spelling | 3 top-level PASS |
| Account ownership classification/refusal seam | 2 top-level PASS |
| Account ownership реальные lifecycle tests | 2 SKIP: административных прав нет |
| Временные observation probes: два data-loss случая, limited cost, nested stale memo | 4 top-level PASS, измерения приведены выше |
| Targeted build с `-gcflags=-m=2` | exit 0, SID fix и scratch escape подтверждены |

Всего **36 адресных тестов PASS, 2 SKIP**, плюс 4 временных measurement probes.
Probe PASS означает, что fixture и измерение отработали; это не PASS
требуемого исправленного поведения. Файлы probes удалены после измерений.
Ни один запущенный тест не упал. Полные suite/lint/vet и реальные
account/conhost boundary-прогоны текущего SHA локально не выполнялись.

Для `e67a380` команда `gh run list --commit <SHA>` вернула **пустой список**.
Последний найденный успешный CI — [run 35762222235](https://github.com/PHPCraftdream/wuserbox/actions/runs/35762222235),
SHA `08992d9d79b6218a3ef75f56e03bf233986f61af`: Test, Delete boundary,
Registry hive picture и Own console measurement завершились success.
Это на 28 коммитов раньше проверенного HEAD; выдавать его за проверку
текущего среза нельзя. Новый CI из этого ревью не запускался, push не делался.

## Порядок перед выпуском

1. Закрыть P2-1: reserved guard по всем компонентам legacy path.
2. Закрыть P2-2: полный path preflight до любых профильных удалений.
3. Получить CI итогового SHA с обязательными boundary/hive/own-console gates;
   локальные PASS и административные SKIP этого не заменяют.
4. Затем оптимизировать P3 с сохранением filesystem/alias semantics и
   счётчиками именно той формы работы, которую ускоряют.
