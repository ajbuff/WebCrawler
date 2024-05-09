import queue
import datetime

from resources import Trademark, Dumby
from helpers import globalTimeout

def process_candidate(trademark, domain, output_directory, save_queue, messages_queue):
    try:
        _process_candidate(
            trademark, domain, output_directory, save_queue, messages_queue
        )
    except Exception as e:
        print(f"Failed to process candidate {trademark} : {domain} with error {e}")
        messages_queue.put(f"{trademark} : {domain} : FAILURE")


@globalTimeout()
def _process_candidate(trademark_name, domain, output_directory, save_queue, messages_queue):
    stack = []
    buffer_queue = queue.Queue()
    name = trademark_name

    try:
        trademark = Trademark(trademark_name, domain, output_directory, messages_queue)

        start_time = datetime.datetime.now()
        dumby = Dumby(trademark_name, domain, messages_queue, start_time)
    except Exception as candidate_error:
        trademark.error_logger.error(
            f"Failed to create trademark object for {name} : {domain} with error {candidate_error}"
        )
        total_time = datetime.datetime.now() - start_time
        formatted_time = str(total_time)
        messages_queue.put(f"{name} : {domain} : {formatted_time} : FAILURE")
        return

    stack.append(trademark)

    while stack:
        current = stack.pop()

        try:
            current.process(stack)
        except Exception as processing_error:
            trademark.error_logger.error(
                f"Failed to process candidate {current} with error {processing_error}"
            )
            buffer_queue.put(current)
            continue

        buffer_queue.put(current)

    while not buffer_queue.empty():
        item = buffer_queue.get()
        save_queue.put(item)
    
    save_queue.put(dumby)
