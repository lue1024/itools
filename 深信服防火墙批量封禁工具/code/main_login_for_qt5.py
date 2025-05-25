import sys
import pandas as pd
import re
from datetime import datetime,date
from ipaddress import IPv4Address, AddressValueError
import requests
import json

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
                             QCheckBox, QRadioButton, QTreeWidget, QTreeWidgetItem,
                             QFileDialog, QMessageBox, QHBoxLayout, QVBoxLayout)
from PyQt5.QtCore import QTimer

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLineEdit, QPushButton, QToolBar)
# Suppress only the single InsecureRequestWarning from urllib3.
# import urllib3
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_auth_token(url, username, passwd):
    # 登录获取 token
    url_full = f"https://{url}/api//v1/namespaces/@namespace/login"
    payload = {
        "name": username,
        "password": passwd
    }
    headers = {
        'Content-Type': "application/json"
    }
    try:
        response = requests.post(url_full, data=json.dumps(payload), headers=headers, verify=False, timeout=10)
        response_data = response.json()
        token = response_data.get("data", {}).get("loginResult", {}).get("token")
        return token
    except Exception:
        return None

def keep_token_alive(url, token):
    """保持token活跃"""
    url_full = f"https://{url}/api//v1/namespaces/@namespace/login"
    headers = {
        'Content-Type': "application/json",
        'token': token
    }
    try:
        response = requests.get(url_full, headers=headers, verify=False, timeout=10)
        if response.status_code == 200 and response.json().get("code") == 0:
            print("Token保活成功")
            return True
        else:
            print(f"Token保活失败: {response.text}")
            return False
    except Exception as e:
        print(f"Token保活请求错误: {e}")
        return False

def create_ip_group(host, ip_list, name, token):
    """
    创建一个网络对象组，包含多个IP地址
    """
    url = f"https://{host}/api//v1/namespaces/@namespace/ipgroups"
    ip_ranges = [{"start": ip} for ip in ip_list]
    payload = {
        "ipRanges": ip_ranges,
        "name": name,
        "businessType": "IP"
    }
    headers = {
        'Content-Type': "application/json",
        'token': token
    }
    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers, verify=False, timeout=20)
        return response
    except requests.exceptions.RequestException:
        return None

def sxf_bank_Groups(host, name, group, srcIpGroups, token):
    """
    新建一个策略并且封禁一个对象
    """
    url = f"https://{host}/api/v1/namespaces/@namespace/appcontrols/policys"
    payload = {
        "name": name,
        "description": "",
        "enable": True,
        "group": group,
        "labels": [],
        "src": {
            "srcZones": [],
            "srcAddrs": {
                "srcAddrType": "NETOBJECT",
                "srcIpGroups": srcIpGroups
            }
        },
        "dst": {
            "dstZones": [],
            "dstAddrs": {
                "dstAddrType": "NETOBJECT",
                "dstIpGroups": ["全部"]
            },
            "services": ["any"],
            "applications": ["全部"]
        },
        "action": 0,
        "schedule": "全天",
        "advanceOption": {
            "logEnable": False,
            "autoSynDNS": False,
            "keepAlive": 0
        },
        "isdefault": False,
        "hits": 0
    }
    headers = {
        'Content-Type': "application/json",
        'Accept-Charset': "UTF-8",
        'token': token
    }
    try:
        response = requests.post(url, data=json.dumps(payload, ensure_ascii=False).encode("UTF-8"),
                                 headers=headers, verify=False, timeout=20)
        return response
    except requests.exceptions.RequestException:
        return None

def update_policy_src_groups(host, policy_id, new_src_groups, token, check_group_existence: bool = True):
    """
    修改防火墙策略的源地址组（追加模式）
    """
    if not isinstance(new_src_groups, list):
        QMessageBox.critical(None, "参数类型错误", "new_src_groups 必须是列表")
        raise ValueError("new_src_groups 必须是列表")
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    valid_groups = []
    if check_group_existence:
        for group in new_src_groups:
            check_url = f"{host}/api/v1/namespaces/@namespace/ipgroups/{group}"
            try:
                response = requests.get(check_url, headers={'token': token}, verify=False, timeout=10)
                if response.status_code == 200:
                    valid_groups.append(group)
                else:
                    QMessageBox.critical(None, "地址组不存在", f": {group} | 响应: {response.text}")
            except requests.exceptions.RequestException as e:
                QMessageBox.critical(None, "地址组验证失败", f" {group} | 错误: {str(e)}")
                raise
        if not valid_groups:
            QMessageBox.critical(None, "没有有效的地址组可添加", "")
            return False
        new_src_groups = valid_groups
    try:
        get_url = f"{host}/api/v1/namespaces/@namespace/appcontrols/policys/{policy_id}"
        response = requests.get(get_url, headers={'token': token}, verify=False, timeout=15)
        response.raise_for_status()
        policy_data = response.json().get('data', {})
        if not policy_data:
            QMessageBox.critical(None, "获取到的策略数据为空", "")
            return False
    except requests.exceptions.HTTPError:
        QMessageBox.critical(None, "获取策略失败", f"HTTP {response.status_code}: {response.text}")
        return False
    except json.JSONDecodeError:
        QMessageBox.critical(None, "响应数据不是有效的JSON格式", "")
        return False
    except Exception as e:
        QMessageBox.critical(None, "请求错误", str(e))
        return False
    current_groups = policy_data.get('src', {}).get('srcAddrs', {}).get('srcIpGroups', [])
    updated_groups = list(set(current_groups + new_src_groups))
    update_payload = {
        **policy_data,
        "src": {
            **policy_data.get('src', {}),
            "srcAddrs": {
                **policy_data.get('src', {}).get('srcAddrs', {}),
                "srcIpGroups": updated_groups
            }
        }
    }
    try:
        put_url = f"{host}/api/v1/namespaces/@namespace/appcontrols/policys/{policy_id}"
        response = requests.patch(put_url,
                                  headers={'token': token, 'Content-Type': 'application/json; charset=utf-8'},
                                  data=json.dumps(update_payload, ensure_ascii=False).encode('utf-8'),
                                  verify=False, timeout=20)
        response.raise_for_status()
        if response.json().get('code', 0) == 0:
            QMessageBox.information(None, "更新成功", f"策略 {policy_id} 更新成功 | 新增组: {new_src_groups}")
            return True
        else:
            QMessageBox.critical(None, "API返回错误", f": {response.text}")
            return False
    except requests.exceptions.Timeout:
        QMessageBox.critical(None, "请求超时", "请检查网络连接")
        return False
    except requests.exceptions.SSLError:
        QMessageBox.critical(None, "SSL证书验证失败", "尝试使用 False=False")
        return False
    except Exception as e:
        QMessageBox.critical(None, "更新策略错误", str(e))
        return False

def modify_ip_group(host, group_name, new_ips, token):
    """
    修改现有的网络对象组，向其添加新的IP地址
    """
    try:
        get_url = f"https://{host}/api/v1/namespaces/@namespace/ipgroups/{group_name}"
        headers = {'Content-Type': "application/json", 'token': token}
        response = requests.get(get_url, headers=headers, verify=False, timeout=10)
        if response.status_code != 200:
            return f"获取IP组信息失败: {response.text} (状态码: {response.status_code})"
        group_data = response.json().get("data", {})
        existing_ips = [ip_range.get("start") for ip_range in group_data.get("ipRanges", [])]
        duplicate_ips = set(new_ips) & set(existing_ips)
        if duplicate_ips:
            return f"以下IP已存在于组中: {', '.join(duplicate_ips)}"
        combined_ips = existing_ips + new_ips
        update_url = f"https://{host}/api/v1/namespaces/@namespace/ipgroups/{group_name}"
        payload = {
            "ipRanges": [{"start": ip} for ip in combined_ips],
            "name": group_name,
            "businessType": "IP"
        }
        update_response = requests.put(update_url,
                                       data=json.dumps(payload),
                                       headers=headers, verify=False, timeout=20)
        if update_response.status_code in [200, 201]:
            return "成功"
        else:
            return f"更新IP组失败: {update_response.text} (状态码: {update_response.status_code})"
    except requests.exceptions.RequestException as e:
        return f"网络请求异常: {str(e)}"
    except Exception as e:
        return f"处理过程中发生错误: {str(e)}"

def get_ip_group_count(host, group_name, token):
    """
    查询网络对象组中已存在的IP地址个数
    """
    try:
        get_url = f"https://{host}/api/v1/namespaces/@namespace/ipgroups/{group_name}"
        headers = {'Content-Type': "application/json", 'token': token}
        response = requests.get(get_url, headers=headers, verify=False, timeout=10)
        if response.status_code != 200:
            return -1, f"获取IP组信息失败: {response.text} (状态码: {response.status_code})"
        group_data = response.json().get("data", {})
        ip_ranges = group_data.get("ipRanges", [])
        ip_count = len(ip_ranges)
        return ip_count, ""
    except requests.exceptions.RequestException as e:
        return -1, f"网络请求异常: {str(e)}"
    except Exception as e:
        return -1, f"处理过程中发生错误: {str(e)}"

class IPBlockerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IP自动封禁系统 v2.5 [Qt版]")
        self.token = ""
        self.url = ""
        self.df = pd.DataFrame(columns=['IP地址', '封禁时间', '操作人员'])
        self.current_file = None
        self.banned_list = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.keep_token)
        self.initUI()
        self.show()

    def initUI(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout()

        menubar = self.menuBar()
       
        # 顶部菜单
        # file_menu = menubar.addMenu('文件')
        # file_menu.addAction(self.new_action)
        # file_menu.addAction(self.open_action)
        # file_menu.addAction(self.save_action)

        # ----------------------------------------
        # 顶部服务器连接面板
        top_layout = QHBoxLayout()
        lbl_server = QLabel("服务器地址:")
        # lbl_server.clicked.connect(self.show_today_report)
        lbl_server.mousePressEvent = lambda event: self.show_today_report()  # 统计
        top_layout.addWidget(lbl_server)
        self.server_entry = QLineEdit()
        self.server_entry.setFixedWidth(150)
        top_layout.addWidget(self.server_entry)
        # self.server_entry.setSpacing(0)

        top_layout.addWidget(QLabel("用户名:"))
        self.user_entry = QLineEdit()
        self.user_entry.setFixedWidth(180)
        top_layout.addWidget(self.user_entry)

        top_layout.addWidget(QLabel("密码:"))
        self.pass_entry = QLineEdit()
        self.pass_entry.setFixedWidth(180)
        self.pass_entry.setEchoMode(QLineEdit.Password)
        top_layout.addWidget(self.pass_entry)

        self.login_btn = QPushButton("登录")
        self.login_btn.clicked.connect(self.connect_server)
        top_layout.addWidget(self.login_btn)

        self.connection_status = QLabel("未连接")
        self.connection_status.setStyleSheet("color: red")
        top_layout.addWidget(self.connection_status)

        main_layout.addLayout(top_layout)

        # 主内容区：左侧控制面板和右侧记录显示
        middle_layout = QHBoxLayout()

        # 左侧控制面板
        left_layout = QVBoxLayout()
        btn_select_file = QPushButton("选择记录文件")
        btn_select_file.clicked.connect(self.select_record_file)
        # btn_select_file.setFixedWidth(250)
        left_layout.addWidget(btn_select_file)

        hbox_import = QHBoxLayout()
        btn_batch = QPushButton("批量导入封禁IP")
        btn_batch.clicked.connect(self.batch_import_ips)
        btn_batch.setFixedWidth(250)

        hbox_import.addWidget(btn_batch)
        self.chk_join = QCheckBox("加入对象")
        hbox_import.addWidget(self.chk_join)
        left_layout.addLayout(hbox_import)

        left_layout.addWidget(QLabel("IP地址:"))
        self.ip_entry = QLineEdit()
        left_layout.addWidget(self.ip_entry)
        self.ip_entry.setFixedWidth(250)

        lbl_operator = QLabel("操作人员:")
        lbl_operator.setStyleSheet("color: blue")
        left_layout.addWidget(lbl_operator)
        self.operator_entry = QLineEdit()
        self.operator_entry.setFixedWidth(250)
        left_layout.addWidget(self.operator_entry)

        lbl_group = QLabel("策略组名:")
        lbl_group.setStyleSheet("color: green")
        left_layout.addWidget(lbl_group)
        self.group_entry = QLineEdit()
        self.group_entry.setFixedWidth(250)
        left_layout.addWidget(self.group_entry)

        # 操作模式单选按钮
        self.radio_add = QRadioButton("新建策略")
        self.radio_modify = QRadioButton("修改策略")
        self.radio_add.setChecked(True)
        radio_layout = QHBoxLayout()
        radio_layout.addWidget(self.radio_add)
        radio_layout.addWidget(self.radio_modify)
        left_layout.addLayout(radio_layout)

        left_layout.addWidget(QLabel("修改的策略名:"))
        self.appname_entry = QLineEdit()
        self.appname_entry.setFixedWidth(250)
        left_layout.addWidget(self.appname_entry)

        btn_check = QPushButton("检测是否被封禁")
        btn_check.clicked.connect(self.check_ip_status)
        left_layout.addWidget(btn_check)

        lbl_ipgroups = QLabel("加入的对象名称:")
        lbl_ipgroups.setStyleSheet("color: green")
        left_layout.addWidget(lbl_ipgroups)
        self.ipgroups_name = QLineEdit()
        self.ipgroups_name.setFixedWidth(250)
        left_layout.addWidget(self.ipgroups_name)
        

        btn_ban_ip = QPushButton("封禁IP")
        btn_ban_ip.clicked.connect(self.add_ban_ip)
        left_layout.addWidget(btn_ban_ip)

        self.result_label = QLabel("")
        self.result_label.setStyleSheet("color: green")
        left_layout.addWidget(self.result_label)



        left_layout.addStretch()
        middle_layout.addLayout(left_layout)

        # 右侧记录显示
        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setHeaderLabels(['IP地址', '封禁时间', '操作人员'])
        self.tree.setColumnWidth(0, 150)
        self.tree.setColumnWidth(1, 150)
        self.tree.setColumnWidth(2, 150)
        middle_layout.addWidget(self.tree)

        main_layout.addLayout(middle_layout)
        central.setLayout(main_layout)

    def show_today_report(self):
        # 获取今天封禁的个数
        today = date.today().strftime("%Y-%m-%d")
        count = self.df[self.df["封禁时间"].astype(str).str.startswith(today)].shape[0]
        QMessageBox.information(self, "统计", f"{today}封禁的个数为：{count}")
        
        # return count
    
    def connect_server(self):
        server = self.server_entry.text().strip()
        username = self.user_entry.text().strip()
        password = self.pass_entry.text().strip()
        if not server or not username or not password:
            QMessageBox.critical(self, "错误", "服务器地址、用户名和密码都必须填写")
            return
        try:
            self.url = server
            self.token = get_auth_token(server, username, password)
            if not self.token:
                raise Exception("认证失败")
            self.connection_status.setText("已连接")
            self.connection_status.setStyleSheet("color: green")
            QMessageBox.information(self, "成功", "服务器连接成功")
            # 启动定时器, 每小时保活
            self.timer.start(3600000)
        except Exception as e:
            self.connection_status.setText("连接失败")
            self.connection_status.setStyleSheet("color: red")
            QMessageBox.critical(self, "连接错误", f"无法连接到服务器: {str(e)}")

    def keep_token(self):
        rett = keep_token_alive(self.url, self.token)
        if rett:
            self.connection_status.setText("已连接")
            self.connection_status.setStyleSheet("color: green")
        else:
            self.connection_status.setText("未连接")
            self.connection_status.setStyleSheet("color: red")

    def parse_banned_ips(self):
        self.banned_list = []
        for _, row in self.df.iterrows():
            ip_str = str(row['IP地址']).strip()
            time = row['封禁时间']
            operator = row['操作人员']
            if '-' in ip_str:
                try:
                    start_ip, end_ip = ip_str.split('-')
                    start = IPv4Address(start_ip.strip())
                    end = IPv4Address(end_ip.strip())
                    self.banned_list.append({
                        'type': 'range',
                        'start': start,
                        'end': end,
                        'time': time,
                        'operator': operator
                    })
                except AddressValueError:
                    QMessageBox.critical(self, "错误", f"无效的IP范围格式：{ip_str}")
            else:
                try:
                    ip = IPv4Address(ip_str)
                    self.banned_list.append({
                        'type': 'single',
                        'ip': ip,
                        'time': time,
                        'operator': operator
                    })
                except AddressValueError:
                    QMessageBox.critical(self, "错误", f"无效的IP地址：{ip_str}")

    def update_treeview(self):
        self.tree.clear()
        for _, row in self.df.iterrows():
            item = QTreeWidgetItem([str(row['IP地址']), str(row['封禁时间']), str(row['操作人员'])])
            self.tree.addTopLevelItem(item)

    def load_excel_data(self, file_path):
        try:
            self.df = pd.read_excel(file_path)
            self.current_file = file_path
            self.parse_banned_ips()
            self.update_treeview()
            QMessageBox.information(self, "成功", f"已加载文件：{file_path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"读取文件失败：{str(e)}")

    def select_record_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择Excel文件", "", "Excel 文件 (*.xlsx)")
        if file_path:
            self.load_excel_data(file_path)

    def batch_import_ips(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择Excel文件", "", "Excel 文件 (*.xlsx)")
        if not file_path:
            return
        operator = self.operator_entry.text().strip()
        if not operator:
            QMessageBox.critical(self, "错误", "请填写操作人员")
            return
        try:
            df_input = pd.read_excel(file_path)
            ips = df_input['IP地址'].astype(str).str.strip().dropna().unique().tolist()
            # 验证IP格式
            valid_ips = []
            invalid_ips = []
            for ip in ips:
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', ip):
                    valid_ips.append(ip)
                else:
                    invalid_ips.append(ip)
            # 分类已封禁和未封禁IP
            banned_ip = []
            sealed_off_ip = []
            for ip in valid_ips:
                if self.check_only_ip(ip):
                    banned_ip.append(ip)
                else:
                    sealed_off_ip.append(ip)
            group_names = []
            total = len(banned_ip)
            if total > 0:
                batch_size = 200
                num_batches = (total + batch_size - 1) // batch_size
                if self.chk_join.isChecked():
                    # 加入已存在的对象
                    if num_batches == 1:
                        if total > 190:
                            QMessageBox.critical(self, "添加失败",
                                                 f"对象个数为{total}个无法加入\n请确保加入对象小于190个")
                            return
                        ipgroups_name = self.ipgroups_name.text().strip()
                        if not ipgroups_name:
                            QMessageBox.critical(self, "未输入加入的对象名", "要加入的对象名称")
                            return
                        count, errmsg = get_ip_group_count(self.url, ipgroups_name, self.token)
                        if count == -1:
                            QMessageBox.critical(self, "API调用失败", "查询对象个数失败,可能是登录失效")
                            return
                        if count + total > 200:
                            QMessageBox.critical(self, "添加失败", "对象个数大于200个无法加入\n请更换对象")
                            return
                        rett = modify_ip_group(self.url, ipgroups_name, banned_ip, self.token)
                        if '成功' not in rett:
                            QMessageBox.critical(self, "添加对象API调用失败", rett)
                            return
                        new_records = []
                        for ip in banned_ip:
                            new_records.append({
                                'IP地址': ip,
                                '封禁时间': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                '操作人员': operator
                            })
                        self.df = pd.concat([self.df, pd.DataFrame(new_records)], ignore_index=True)
                        self.save_records()
                        self.parse_banned_ips()
                        self.update_treeview()
                        result_msg = [f"成功封禁IP数量: {len(banned_ip)}"]
                        QMessageBox.information(self, "导入结果", "\n".join(result_msg))
                        return
                # 批量封禁
                for batch_num in range(num_batches):
                    start = batch_num * batch_size
                    end = start + batch_size
                    batch_ips = banned_ip[start:end]
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    group_name = f"BLOCK_{timestamp}_BATCH{batch_num+1}"
                    group_names.append(group_name)
                    policy_name = f"POLICY_{group_name}"
                    create_resp = create_ip_group(host=self.url, ip_list=batch_ips, name=group_name, token=self.token)
                    if not create_resp or create_resp.status_code not in [200, 201]:
                        error_msg = f"IP组创建失败（批次{batch_num+1}）:\n{create_resp.text if create_resp else '无响应'}"
                        QMessageBox.critical(self, "API错误", error_msg)
                        continue
                if self.radio_add.isChecked():  # 选择新建对象
                    group_name_entry = self.group_entry.text().strip()
                    if not group_name_entry:
                        QMessageBox.critical(self, "未输入策略组", "请输入策略组")
                        return
                    for group_name in group_names:
                        policy_name = f"POLICY_{group_name}"
                        policy_resp = sxf_bank_Groups(host=self.url, name=policy_name,
                                                     group=group_name_entry,
                                                     srcIpGroups=[group_name],
                                                     token=self.token)
                        if not policy_resp or policy_resp.status_code not in [200, 201]:
                            error_msg = f"策略创建失败（组 {group_name}）:\n{policy_resp.text if policy_resp else '无响应'}"
                            QMessageBox.critical(self, "API错误", error_msg)
                else:
                    app_name = self.appname_entry.text().strip()
                    if not app_name:
                        QMessageBox.critical(self, "未输入修改的策略名称", "修改的策略名称")
                        return
                    update_policy_src_groups(self.url, app_name, group_names, self.token)
                new_records = []
                for ip in banned_ip:
                    new_records.append({
                        'IP地址': ip,
                        '封禁时间': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        '操作人员': operator
                    })
                self.df = pd.concat([self.df, pd.DataFrame(new_records)], ignore_index=True)
                self.save_records()
                self.parse_banned_ips()
                self.update_treeview()
                result_msg = [
                    f"成功封禁IP数量: {len(banned_ip)}",
                    f"重复封禁IP数量: {len(sealed_off_ip)}",
                    f"无效IP数量: {len(invalid_ips)}"
                ]
                QMessageBox.information(self, "导入结果", "\n".join(result_msg))
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导入过程中发生异常: {str(e)}")

    def check_ip_status(self):
        input_ip = self.ip_entry.text().strip()
        try:
            target = IPv4Address(input_ip)
        except AddressValueError:
            QMessageBox.critical(self, "错误", "无效的IP地址格式")
            return
        result_text = f"IP {input_ip} 未被封禁"
        color = "green"
        for item in self.banned_list:
            if item['type'] == 'single' and target == item['ip']:
                result_text = f"IP {input_ip} 已被封禁\n封禁时间：{item['time']}\n操作人员：{item['operator']}"
                color = "red"
                break
            elif item['type'] == 'range' and (item['start'] <= target <= item['end']):
                result_text = f"IP {input_ip} 在封禁范围内\n封禁时间：{item['time']}\n操作人员：{item['operator']}"
                color = "red"
                break
        self.result_label.setText(result_text)
        self.result_label.setStyleSheet(f"color: {color}")

    def check_only_ip(self, ip):
        try:
            target = IPv4Address(ip)
        except AddressValueError:
            QMessageBox.critical(self, "错误", "无效的IP地址格式")
            return False
        for item in self.banned_list:
            if item['type'] == 'single' and target == item['ip']:
                return False
            if item['type'] == 'range' and (item['start'] <= target <= item['end']):
                return False
        return True

    def add_ban_ip(self):
        input_ip = self.ip_entry.text().strip()
        operator = self.operator_entry.text().strip()
        if not input_ip or not operator:
            QMessageBox.critical(self, "错误", "所有字段必须填写")
            return
        try:
            target = IPv4Address(input_ip)
        except AddressValueError:
            QMessageBox.critical(self, "错误", "无效的IP地址格式")
            return
        result_text = f"IP {input_ip} 封禁成功"
        color = "green"
        for item in self.banned_list:
            if item['type'] == 'single' and target == item['ip']:
                result_text = f"IP {input_ip} 之前已被封禁\n封禁时间：{item['time']}\n操作人员：{item['operator']}"
                color = "red"
                self.result_label.setText(result_text)
                self.result_label.setStyleSheet(f"color: {color}")
                return
            elif item['type'] == 'range' and (item['start'] <= target <= item['end']):
                result_text = f"IP {input_ip} 之前已被封禁范围内\n封禁时间：{item['time']}\n操作人员：{item['operator']}"
                color = "red"
                self.result_label.setText(result_text)
                self.result_label.setStyleSheet(f"color: {color}")
                return
        if color == "green":
            try:
                if self.radio_modify.isChecked():
                    ipgroups_name = self.ipgroups_name.text().strip()
                    if not ipgroups_name:
                        QMessageBox.critical(self, "未输入加入的对象名", "要加入的对象名称")
                        return
                    rett = modify_ip_group(self.url, ipgroups_name, [input_ip], self.token)
                else:
                    group_name_entry = self.group_entry.text().strip()
                    if not group_name_entry:
                        QMessageBox.critical(self, "未输入策略组", "请输入策略组")
                        return
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    group_name = f"BLOCK_{timestamp}_BATCH"
                    policy_name = f"POLICY_{group_name}"
                    create_resp = create_ip_group(host=self.url, ip_list=[input_ip], name=group_name, token=self.token)
                    if not create_resp or create_resp.status_code not in [200, 201]:
                        QMessageBox.critical(self, "API错误", "策略创建失败")
                        return
                    policy_resp = sxf_bank_Groups(host=self.url, name=policy_name,
                                                 group=group_name_entry,
                                                 srcIpGroups=[group_name],
                                                 token=self.token)
                    if not policy_resp or policy_resp.status_code not in [200, 201]:
                        QMessageBox.critical(self, "API错误", "策略创建失败,请重新尝试")
                        return
                    rett = "创建成功"
                QMessageBox.information(self, "提示", rett)
                if '成功' not in rett:
                    return
            except Exception as e:
                QMessageBox.critical(self, "封禁错误", f"封禁IP时出错: {str(e)}\n可能是登录已过期")
                return
            new_record = {
                'IP地址': input_ip,
                '封禁时间': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                '操作人员': operator
            }
            self.df = pd.concat([self.df, pd.DataFrame([new_record])], ignore_index=True)
            self.parse_banned_ips()
            self.update_treeview()
            self.save_records()
            self.ip_entry.clear()

    def save_records(self):
        try:
            save_path = self.current_file if self.current_file else "default_records.xlsx"
            save_df = self.df[['IP地址', '封禁时间', '操作人员']].copy()
            save_df.to_excel(save_path, index=False)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"记录保存失败: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IPBlockerApp()
    window.resize(1000, 600)
    sys.exit(app.exec_())
