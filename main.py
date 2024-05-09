import multiprocessing
import os
import time

from concurrent.futures import ThreadPoolExecutor

from config import OUTPUT_DIRECTORY, CANDIDATE_DOMAINS_PATH, MAX_WORKERS
from helpers import (
    create_directory,
    read_json_file,
    load_trademarks,
    get_total_tasks_by_trademark,
    get_completed_tasks_by_trademark,
    get_remaining_tasks_by_trademark,
)
from process import process_candidate


def messages_worker(messages_queue, completed_tasks_file):
    completed_tasks = 0
    start_time = time.time()

    with open(completed_tasks_file, "a") as file:
        while True:
            message = messages_queue.get()
            if message is None:
                break

            file.write(f"{message}\n")
            file.flush()

            completed_tasks += 1

            if completed_tasks % 2 == 0:
                current_time = time.time()
                elapsed_time = current_time - start_time
                tasks_per_minute = (completed_tasks / elapsed_time) * 60
                print(
                    f"Completed {completed_tasks} jobs. Rate: {tasks_per_minute:.2f} jobs/min\r",
                    end="",
                )


def save_worker(save_queue):
    while True:
        item = save_queue.get()
        if item is None:
            break

        try:
            item.save()
        except Exception as e:
            print(f"Failed to process item {item} with error {e}")


def get_tasks_for_trademark(
    trademark, candidate_domains_file, output_directory, save_queue, messages_queue, completed_tasks_file
):
    total_tasks = get_total_tasks_by_trademark(trademark, candidate_domains_file)
    completed = get_completed_tasks_by_trademark(trademark, completed_tasks_file)
    remaining_tasks = get_remaining_tasks_by_trademark(total_tasks, completed)

    print(f"Total tasks for {trademark} : {len(total_tasks)}")
    print(f"Completed tasks for {trademark} : {len(completed)}")
    print(f"Remaining tasks for {trademark} : {len(remaining_tasks)}")

    if not remaining_tasks:
        print(f"Skipping {trademark} as all tasks are completed")
        return

    base_output_directory = output_directory

    execute_tasks(
        trademark,
        remaining_tasks,
        base_output_directory,
        save_queue,
        messages_queue,
    )


def get_trademarks_and_execute_tasks(output_directory, save_queue, messages_queue, completed_tasks_file):
    candidate_domains_file = read_json_file(CANDIDATE_DOMAINS_PATH)
    trademarks = sorted(load_trademarks(candidate_domains_file), key=len, reverse=True)

    customIndices = input(
        "Do you want to process a custom range of trademarks? (y/n): "
    )

    if customIndices.lower() == "y":
        startIndex = input("Enter the start index for the trademarks: ")
        startIndex = int(startIndex)
        endIndex = input("Enter the end index for the trademarks: ")
        endIndex = int(endIndex)

        if startIndex < 0 or endIndex < 0 or startIndex > endIndex:
            print("Invalid start and end index")
            return

        trademarks = trademarks[startIndex:endIndex]
        print(f"Processing trademarks: {trademarks}")

        confirmation = input("Do you want to continue? (y/n): ")

        if confirmation.lower() == "n":
            return
    if customIndices.lower() == "n":
        num_trademarks = len(trademarks)
        confirmation = input(f"Do you want to process all {num_trademarks} trademarks? (y/n): ")

        if confirmation.lower() == "n":
            return
        else:
            print("Processing all trademarks")

    for trademark in trademarks:
        print(f"Processing trademark {trademark}")
        get_tasks_for_trademark(
            trademark,
            candidate_domains_file,
            output_directory,
            save_queue,
            messages_queue,
            completed_tasks_file
        )


def execute_tasks(trademark, tasks, output_directory, save_queue, message_queue):
    print("Hiring workers for trademark", trademark)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(
                process_candidate,
                trademark,
                task,
                output_directory,
                save_queue,
                message_queue,
            )
            for task in tasks
        ]

    while not save_queue.empty():
        time.sleep(1)

    print(
        f"All workers completed their tasks for trademark: {trademark} and are now fired."
    )

    return


def main():
    # 1. Get the system hostname (we will use this for the completion log)
    hostname = os.uname().nodename.split(".")[0]

    # 2. Create the output directory
    output_directory = OUTPUT_DIRECTORY

    create_directory(output_directory)

    # 3. Completed tasks file name
    completed_tasks_file = os.path.join(output_directory, f"{hostname}_completed_tasks")

    # 4. Create a multiprocessing manager
    manager = multiprocessing.Manager()
    messages_queue = manager.Queue()

    # 5. Create a save queue and start the save and messages processes
    save_queue = multiprocessing.Queue()
    save_proc = multiprocessing.Process(target=save_worker, args=(save_queue,))
    messages_proc = multiprocessing.Process(
        target=messages_worker, args=(messages_queue, completed_tasks_file)
    )

    save_proc.start()
    messages_proc.start()

    try:
        get_trademarks_and_execute_tasks(output_directory, save_queue, messages_queue, completed_tasks_file)
    except Exception as e:
        print(f"Failed to generate tasks with error {e}")
        return
    finally:
        save_queue.put(None)
        messages_queue.put(None)

        save_proc.join()
        messages_proc.join()


if __name__ == "__main__":
    main()
