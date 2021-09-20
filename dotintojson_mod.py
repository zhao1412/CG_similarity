import os
import sys
import json

# walk through CG files rooted in branch_directory and copy the content of dot file inspectively into the corresponding json file in main_directory
def copy_dot_into_json(main_directory, branch_directory):
    """walk through CG files rooted in branch_directory 
    and copy the content of dot file inspectively into 
    the corresponding json file in main_directory

    Args:
        main_directory (a path): the directory contains  
                                json files
        branch_directory (a path): the directory contains 
                                different malicious codes' 
                                analysis directories
    """

    for root, dirs, files in os.walk(branch_directory):
        split_path = os.path.split(root)
        head = split_path[0]
        tail = split_path[1]
        if tail == 'CG':
            try:
                # 创建json文件
                split_path_2 = os.path.split(head)
                fp_json = open(main_directory + '\\' + split_path_2[1] + '.json', 'w+')
            except OSError:
                sys.exit('Error at opening file fucntion1!')
            
            try:
                # dot文件内容拷贝进json
                fp_dot = open(root + '\\' + files[0], 'r')
                dot_content = fp_dot.read()
                fp_json.write(dot_content)
            except:
                sys.exit('Error at copying file function1!')
            
            try:
                # 关闭文件
                fp_json.close()
                fp_dot.close()
            except:
                sys.exit('Error at closing file function1!')
    
    return


# find a list of positions, which includes all indexs that sub_string occurs in main_string
# 不一定用得上
def pos_str_occur(main_string, sub_string):
    """找字串的位置

    Args:
        main_string (string): none
        sub_string (string): none
    """
    list_of_pos = []
    pos = -2
    exam_pos = 0
    len_sub = len(sub_string)

    while(pos != -1):
        pos = main_string.find(sub_string, exam_pos)
        if(pos != -1):
            list_of_pos.append(pos)
            exam_pos = pos + len_sub
            if(exam_pos >= len_sub):
                break
    
    return list_of_pos


# modify the content of each json file to make it fit for graph2vec input json form
def modify_json(main_directory):
    """Modify the json files used for graph2vec

    Args:
        main_directory (a path): the directory contains  
                                json files
    """
    # 第6步中用来装CG图的顶点名称字符串的列表
    vertex_list = []


    for root, dirs, files in os.walk(main_directory):
        for file in files:
            try:
                fp = open(f'{main_directory}\\{file}', 'r+')
            except OSError as err:
                sys.exit('Error at opening file function2! Error is:' + format(err))
            json_content = fp.read()

            # 清空文件内容
            fp.truncate(0)
            fp.seek(0)
            # 修改json_content并重新传入
            # 1. 删掉DiGraph CallGraph
            json_content = json_content.replace('DiGraph CallGraph', '', 1)
            # 2. 加"edge": [[
            json_content = json_content.replace('\n', '"edges": [["', 1)
            # 3. 末尾变为]]}
            json_content = json_content.rstrip('\n}')
            json_content = json_content + '"]]}'
            # 4. 中间的\n替换为], [
            json_content = json_content.replace('\n', '"], ["')
            # 5. ->替换为, 
            json_content = json_content.replace('->', '", "')
            # 6. 把图中顶点的名称由字符串改为数字
            json_object = json.loads(json_content)
            # 6. (1)如果某图中边数小于等于一条，不做数字与字符串转换，打出文件名:
            if(len(json_object["edges"]) <= 1):
                fp.write(json_content)
                print(f'{fp.name} has edge not greater than 1, vertices\' form will not be transformed!')
                try:
                    fp.close()
                except:
                    sys.exit('Error at closing file function2!')
                continue
            # 6. (2)将顶点名称存入vertex_list
            for edge in json_object["edges"]:
                if(edge[0] not in vertex_list):
                    vertex_list.append(edge[0])
                if(edge[1] not in vertex_list):
                    vertex_list.append(edge[1])
            # 6. (3)取顶点名称在vertex_list中的索引代替顶点名称
            for edge in json_object["edges"]:
                edge[0] = vertex_list.index(edge[0])
                edge[1] = vertex_list.index(edge[1])
            # 6. (4)将修改好的json_oject重新编码为字符串赋值给json_content
            json_content = json.dumps(json_object)
            # 7. 写入fp
            fp.write(json_content)
            # 8. 清空vertex_list
            vertex_list = []
            try:
                fp.close()
            except:
                sys.exit('Error at closing file function2!')
    return

# 主逻辑执行修改
main_directory = 'C:\\task1\\graph2vec_venv\\oceanlotus_json'
branch_directory = 'C:\\task1\\oceanlotus_exec\\exec\\output'
copy_dot_into_json(main_directory, branch_directory)
modify_json(main_directory)