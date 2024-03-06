from blockcrypto_handler import BlockChainHandler
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('path/to/log_file')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)


def test_blockcrypto_handler(filepath, filename):
    bc_handler = BlockChainHandler(bc_logger=logger)
    bc_req_response, success_cb_req = bc_handler.blockchain_request(action='notarize',
                                                                    file_path=filepath,
                                                                    file_name=f'output_report_{filename}.html')
    sign_resp, return_code = bc_handler.sign_report(filepath)


if __name__ == '__main__':
    test_blockcrypto_handler(filepath='./test_file_repo_demo.txt', filename='test_file_repo_demo.txt')
