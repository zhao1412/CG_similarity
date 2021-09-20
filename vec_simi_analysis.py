import csv
import numpy as np

def read_vec(csv_path):
    """将CG向量表示为{"name" : "file/name", "vector" : [x0, x1, ..., x127]}
    将所有CG向量存到列表vec_list中。

    Args:
        csv_path (a path): 存放graph2vec产生的csv文件的路径。
    """
    # 由于csv文件中第一行是表的列说明，因此count用于在读数据时过滤第一行
    count = 1
    global vec_list
    with open(csv_path, newline = '') as csvfile:
        reader = csv.reader(csvfile)
        # reader将每一行数据存为列表
        for row in reader:
            if(count >= 1):
                count -= 1
                continue
            vec_name = row[0]
            vec_data = row[1:]
            vec_data = np.array(vec_data, dtype = np.float32)
            vec_list.append({"name" : vec_name, "vector" : vec_data})
    return


def simi_calculator(vec1, vec2):
    """计算两个向量的余弦距离。

    Args:
        vec1 (vec_list中的一个向量): 无。
        vec2 (vec_list中的一个向量): 无。
    """
    # 点积结果
    dot_res = np.dot(vec1, vec2)
    # 二范数
    norm2_vec1 = np.linalg.norm(vec1)
    norm2_vec2 = np.linalg.norm(vec2)
    # 余弦值
    cos = dot_res / (norm2_vec1 * norm2_vec2)
    return cos

def simi_matrix(vector_list):
    """函数返回描述向量间相似性的相似度矩阵。相似度矩阵是个n*n方阵，n是向量个数，
    其中第i*j元素表示第i个向量和第j个向量的余弦距离。矩阵为上三角矩阵，对角线元素、
    对角线以下的元素均为0.

    Args:
        vector_list (list): 向量列表，在这里与全局变量vec_list一致
    """
    # 空矩阵建立
    vec_num = len(vector_list)
    res = np.zeros((vec_num, vec_num), dtype = np.float32)
    # 矩阵元素计算
    for vec_index in range(0, vec_num):
        vec = vector_list[vec_index]["vector"]
        for ano_vec_index in range(vec_index + 1, vec_num):
            ano_vec = vector_list[ano_vec_index]["vector"]
            res[vec_index][ano_vec_index] = simi_calculator(vec, ano_vec)
    return res


def simi_bool_matrix(matrix, threshold):
    """对matrix根据相似度阈值做二值化处理。上三角矩阵变为对称阵。

    Args:
        matrix (2-dim list): 相似度矩阵，对应simi_matrix的输出。
        threshold (-1 ~ 1): 相似度阈值。
    """
    vec_num = len(matrix)
    res = np.zeros((vec_num, vec_num), dtype = np.bool_)
    for i in range(0, vec_num):
        for j in range(i + 1, vec_num):
            if(matrix[i][j] >= threshold):
                res[i][j] = True
                # 上三角矩阵对称处理
                res[j][i] = res[i][j]
    return res

'''
    bronk函数利用Bron-Kerbosch算法，根据二值化后的相似度矩阵，将CG向量分成最大完全相似组并输出。
'''
# function determines the neighbors of a given vertex
def neighbor(bool_matrix, vertex):
    index = 0
    neighbor_list = []
    for i in bool_matrix[vertex]:
        if(i == True):
            neighbor_list.append(index)
        index += 1   
    return neighbor_list

# the Bron-Kerbosch recursive algorithm
def bronk(r, p, x):
    """
    Args:
        r (列表): 对应算法中的R集合。
        p (列表): 对应算法中的P集合。
        x (列表): 对应算法中的X集合。
    """
    global write_str, bool_matrix, vec_list
    if len(p) == 0 and len(x) == 0:
        write_str = write_str + '{\n'
        for i in r:
            write_str = write_str + vec_list[i]["name"] + ', \n'
        write_str = write_str + '}\n\n'
        return
    for vertex in p[:]:
        r_new = r[::]
        r_new.append(vertex)
        p_new = [val for val in p if val in neighbor(bool_matrix, vertex)] # p intersects Neighbor(vertex)
        x_new = [val for val in x if val in neighbor(bool_matrix, vertex)] # x intersects Neighbor(vertex)
        bronk(r_new, p_new, x_new)
        p.remove(vertex)
        x.append(vertex)

#############################################

csv_path = 'C:\\task1\\graph2vec_venv\\features\\oceanlotus_cgvec.csv'
output_path = 'C:\\task1\\graph2vec_venv\\result.txt'
threshold = 0.8
# 以上三个参数可以根据需求修改，分别对应向量csv文件的路径，结果输出路径和阈值
vec_list = []

# 1. 读入向量数据。
read_vec(csv_path)

# 2. 计算描述向量间相似度的相似度矩阵，和其对应的二值化矩阵。
similarity_matrix = simi_matrix(vec_list)
bool_matrix = simi_bool_matrix(similarity_matrix, threshold)

# 3. 计算完全最大相似组
# 3.1. 准备p集合
vec_num = len(vec_list)
p = []
for vec_index in range(0, vec_num):
    p.append(vec_index)
# 3.2. 开始计算
# write_str对bronk函数得到的结果做记录，最后写入文件
write_str = '完全最大相似组有：\n'
bronk([], p, [])

# 4. 结果写入文件
with open(output_path, 'w+') as f:
    f.write(write_str)