//  版权 (c) 2023 Uber Technologies, Inc.
//
// 根据Apache许可证2.0版本（“许可证”）获得许可；
// 除非符合许可证，否则您不得使用此文件。
// 您可以在以下位置获取许可证副本：
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// 除非适用法律要求或书面同意，否则软件
// 按“原样”分发，不提供任何明示或暗示的保证或条件。
// 请参阅许可证以了解管理权限和限制的特定语言。

package diagnostic

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"go.uber.org/nilaway/config"
	"golang.org/x/tools/go/analysis"
)

type conflict struct {
	// position 是报告冲突的包独立位置。
	position token.Position
	// flow 存储从源到解引用点的nil流。
	flow nilFlow
	// similarConflicts 存储与此类似的其他冲突。
	similarConflicts []*conflict
}

func (c *conflict) String() string {
	// 为类似冲突构建字符串（即具有相同nil路径的冲突）
	similarConflictsString := ""
	if len(c.similarConflicts) > 0 {
		similarPos := make([]string, len(c.similarConflicts))
		for i, s := range c.similarConflicts {
			similarPos[i] = fmt.Sprintf("\"%s\"", s.flow.nonnilPath[len(s.flow.nonnilPath)-1].consumerPosition.String())
		}

		posString := strings.Join(similarPos[:len(similarPos)-1], ", ")
		if len(similarPos) > 1 {
			posString = posString + ", 和 "
		}
		posString = posString + similarPos[len(similarPos)-1]

		similarConflictsString = fmt.Sprintf("\n\n(相同的nil源还可能在%d个其他地方导致潜在的nil异常: %s.)", len(c.similarConflicts), posString)
	}

	return fmt.Sprintf("检测到潜在的nil异常。观察到从源到解引用点的nil流: %s%s\n", c.flow.String(), similarConflictsString)
}

func (c *conflict) addSimilarConflict(conflict conflict) {
	c.similarConflicts = append(c.similarConflicts, &conflict)
}

// groupConflicts 将具有相同nil路径的冲突分组并更新冲突列表。
func groupConflicts(allConflicts []conflict, pass *analysis.Pass, cwd string) []conflict {
	conflictsMap := make(map[string]int)  // key: nil路径字符串, value: `allConflicts`中的索引
	indicesToIgnore := make(map[int]bool) // 从`allConflicts`中忽略的冲突索引，因为它们已与其他冲突分组

	for i, c := range allConflicts {
		key := pathString(c.flow.nilPath)

		// 单一断言冲突的情况单独处理
		if len(c.flow.nilPath) == 0 && len(c.flow.nonnilPath) == 1 {
			// 这是单一断言冲突的情况。使用non-nil路径中的生产者位置和表示作为键（如果存在），
			// 否则使用生产者和消费者表示作为启发式键来分组冲突。
			p := c.flow.nonnilPath[0]
			key = p.producerRepr + ";" + p.consumerRepr
			if p.producerPosition.IsValid() {
				key = p.producerPosition.String() + ": " + p.producerRepr
			} else {
				// 使用生产者和消费者表示作为键的启发式方法可能并不完美，特别是在两个不同函数中的错误消息完全相同时。
				// 考虑以下示例:
				// ```
				// 	func f1() {
				//		mp := make(map[int]*int)
				//		_ = *mp[0] // 错误消息: "深度读取本地变量 `mp` 缺少防护; 已解引用"
				// 	}
				//
				// 	func f2() {
				//		mp := make(map[int]*int)
				//		_ = *mp[0] // 错误消息: "深度读取本地变量 `mp` 缺少防护; 已解引用"
				// 	}
				// ```
				// 在这里，两个错误消息完全相同，但它们不应被分组在一起，因为它们来自不同的函数。
				// 为了处理这种情况，我们将包含函数名添加到键中。
				conf := pass.ResultOf[config.Analyzer].(*config.Config)
				for _, file := range pass.Files {
					// `fileName`存储相对于当前工作目录的完整文件路径
					fileName := pass.Fset.Position(file.FileStart).Filename
					if fn, err := filepath.Rel(cwd, fileName); err == nil {
						fileName = fn
					}
					// 检查文件是否在范围内且冲突位置是否在同一文件中
					if !conf.IsFileInScope(file) || fileName != c.position.Filename {
						continue
					}
					for _, decl := range file.Decls {
						// 检查冲突位置是否落在函数的位置范围内。如果是，则更新键以包含函数名，并结束遍历。
						if fd, ok := decl.(*ast.FuncDecl); ok {
							functionStart := pass.Fset.Position(fd.Pos()).Offset
							functionEnd := pass.Fset.Position(fd.End()).Offset
							if c.position.Offset >= functionStart && c.position.Offset <= functionEnd {
								key = fd.Name.Name + ":" + key
								break
							}
						}
					}
				}
			}
		}

		if existingConflictIndex, ok := conflictsMap[key]; ok {
			// 分组条件满足。将新冲突添加到`existingConflict`中的`similarConflicts`，并更新groupedConflicts map
			allConflicts[existingConflictIndex].addSimilarConflict(c)
			indicesToIgnore[i] = true
		} else {
			conflictsMap[key] = i
		}
	}

	// 使用分组后的冲突更新groupedConflicts列表
	var groupedConflicts []conflict
	for i, c := range allConflicts {
		if _, ok := indicesToIgnore[i]; !ok {
			groupedConflicts = append(groupedConflicts, c)
		}
	}
	return groupedConflicts
}
