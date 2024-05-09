import os
import shutil
import json
import logging

from anytree import Node
from functools import wraps
from threading import Thread
from config import GLOBAL_TIMEOUT_VALUE


class A_Node(Node):
    separator = " | "

    def __repr__(self):
        return f"A: {self.name}"


class Candidate_Node(Node):
    separator = " | "

    def __repr__(self):
        return f"CANDIDATE: {self.name}"


class CNAME_Node(Node):
    separator = " | "

    def __repr__(self):
        return f"CNAME: {self.name}"


class Redirect_Node(Node):
    separator = " | "

    def __repr__(self):
        return f"REDIRECT: {self.name}"


class Trademark_Node(Node):
    separator = " | "

    def __repr__(self):
        return f"TRADEMARK: {self.name}"


def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def get_completed_tasks_by_trademark(next_trademark, completed_tasks_file):
    filename = completed_tasks_file

    if not os.path.exists(filename):
        return {}

    explored = {}

    with open(filename, "r") as file:
        data = file.readlines()
        for row in data:
            segments = row.split(":")

            if len(segments) != 6:
                continue

            trademark, candidate, minute, second, milisecond, outcome = row.split(":")

            trademark = trademark.strip()
            candidate = candidate.strip()
            outcome = outcome.strip()

            if trademark != next_trademark:
                continue

            explored.update({candidate.strip(): outcome.strip()})

    return explored


def get_remaining_tasks_by_trademark(tasks, completed):
    remaining_tasks = []

    for candidate in tasks:
        if candidate not in completed:
            remaining_tasks.append(candidate)

    return remaining_tasks


def get_logger(output_directory, domain, name):
    LOG_LEVEL = logging.DEBUG

    create_directory(output_directory)

    logger = logging.getLogger(os.path.join(output_directory, name))

    if not logger.handlers:
        logger.setLevel(LOG_LEVEL)

        log_file = os.path.join(output_directory, f"{name}.log")

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(LOG_LEVEL)

        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)

        logger.addHandler(file_handler)

    return logger


def get_total_tasks_by_trademark(trademark, candidate_domains_file):
    total_tasks = candidate_domains_file[trademark]
    return total_tasks


def globalTimeout():
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            res = [None]

            def newFunc():
                try:
                    res[0] = func(*args, **kwargs)
                except Exception as xo:
                    res[0] = xo

            t = Thread(target=newFunc, daemon=True)
            t.start()
            t.join(GLOBAL_TIMEOUT_VALUE)

            if t.is_alive():
                print("Timeout occurred!")
                raise TimeoutException(
                    f"Function {func.__name__} timeout [{GLOBAL_TIMEOUT_VALUE} seconds] exceeded!"
                )

            if isinstance(res[0], BaseException):
                raise res[0]

            return res[0]

        return wrapper

    return deco


def load_trademarks(candidate_domains_file):
    trademark_list = list(candidate_domains_file.keys())
    return trademark_list


def read_json_file(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def remove_directory_if_exists(directory):
    if os.path.exists(directory):
        shutil.rmtree(directory)


class TimeoutException(Exception):
    pass
