# 文档与文件夹说明

1. result.txt
   * 简单说明：该文档中包含海莲花代码的相似组。
   * 详细说明：该文档是根据海莲花代码CG向量（CG图通过graph2vec模型生成的向量）的余弦距离计算的相似组，每个相似组中，两两向量的余弦距离cosx大于0.8。每个相似组均为最大相似组（不在组中的向量无法和组中的全部向量达到0.8的相似度），文档中列出来海莲花代码的所有最大相似组。
2. BasicBlockAnalyzer_linux.py
   * 说明：张曙给我的用于产生代码CG图的脚本。
3. oceanlotus_exec文件夹
   * 说明：./exec/output中包含每个代码的分析结果
4. mod文件夹
   * 说明：里面装有修改过的graph2vec模型的主要脚本，原脚本为graph2vec.py，因为跑的时候有问题（和graph2vec模型的github仓库中issue里的问题一样），直接根据issue中其他用户的该发进行了修改。
5. dotintojson_mod.py
   * 说明：由于graph2vec接收的输入为json，且没有现成的库可以把CG图的dot文件转化为graph2vec所需要的json格式，故这个脚本用于自动将CG图的dot文件转化为graph2vec接收的json文件。使用方式见**脚本使用**。
6. oceanlotus_json文件夹
   * 说明：有dotintojson_mod.py转化dot文件后的json文件，作为graph2vec的输入。
7. features文件夹
   * 说明：包含的./oceanlotus_cgvec.csv是graph2vec的输出文件，包含代码的CG向量。
8. vec_simi_analysis.py
   * 说明：分析向量间的相似性关系，输出为result.txt。分析算法见**算法使用**。使用方式见**脚本使用**。

# 算法说明

* Bron-Kerbosch算法

  * 将每个恶意代码的CG向量作为一个顶点，如果两个向量相似（根据阈值确定）那么视作顶点间具有一条边。

    因而，欲将向量放入组中，且保证组中任意两个向量均相似，这一问题，是求无向图中所有最大完全子图的问题，Bron-Kerbosch是解决算法之一，vec_simi_analysis实现了这个算法。[Bron-Kerbosch Algorithm Wiki](https://en.wikipedia.org/wiki/Bron%E2%80%93Kerbosch_algorithm)

  * 该算法的时间与顶点数是指数级关系，且上机跑的时间与边数相关。我设置相似度阈值为0.8（-1~1），在两核、6G内存虚拟机上跑15分钟左右，阈值越低（边数越多）时间应当越长。
  
  * result.txt中“完全最大相似组”表达的意思为这是由最大完全子图概念而得的相似组。

# 脚本使用

1. dotintojson_mod.py可修改的参数是main_directory，branch_directory。main_directory是输出json文件的文件夹路径，branch_directory是包含代码分析文件夹的output文件夹路径，在这里是CG_similarity/oceanlotus_exec/exec/ouput。
2. vec_simi_analysis.py可修改的参数是csv_path，output_path，threshold。csv_path是graph2vec输出的csv文档的路径，output_path是结果文档result.txt的路径，threshold是相似度阈值。

# 特殊问题说明

1. Error
   * 由于只是注释掉了BasicBlockAnalyzer_linux.py中的line 743，line 797，line 798，以保证脚本不止接收elf文件。在对海莲花代码进行分析时，有时会出现Error，不过出现Error时CG图都已生成，故我没有管这个Error。
2. D1E6文件
   * 以D1E6为名开始的代码，由于其生成的CG图为空，故做相似性分析时删掉了这个文件。
   * 当代码文件的CG图的边数小于等于1时，dotintojson_mod.py会在命令行弹出提示，说明该代码文件不会被转换为json格式。
3. 代码编写
   * 由于太久没有使用Python而且对Python文件处理不熟悉所以花掉了很多时间写dot转json的代码。现在写Python稍微习惯了一些，也掌握了一些库函数的使用，谢谢老师。