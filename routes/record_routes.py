"""
Student record routes for uploading, viewing, and verifying academic records
"""

from flask import Blueprint, request, jsonify, session, g
from datetime import datetime
import traceback
import json

from models.user import User
from models.student_record import StudentRecord
from blockchain import Blockchain, PBFTConsensus
from blockchain.blockchain import BlockchainIntegrityError
from database.db import DatabaseManager
from .auth_routes import login_required, role_required, get_current_user
from utils.logger import get_logger
from utils.singletons import get_blockchain, get_pbft_consensus
from utils.exceptions import BlockchainIntegrityError, PermissionDeniedError

logger = get_logger(__name__)

# Create record blueprint
record_bp = Blueprint('records', __name__, url_prefix='/records')

@record_bp.route('/upload', methods=['POST'])
@login_required
@role_required(['admin'])
def upload_record():
    """
    Upload a new student record (admin only)
    
    Expected JSON:
    {
        "student_id": "string",
        "record_type": "transcript|certificate|diploma|grade_card|achievement|enrollment|completion",
        "record_data": {
            // Record-specific data structure
            "student_name": "string",
            "institution": "string",
            // ... other fields based on record_type
        }
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['student_id', 'record_type', 'record_data']
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}',
                'error_code': 'MISSING_FIELDS'
            }), 400
        
        student_id = data['student_id'].strip()
        record_type = data['record_type'].lower()
        record_data = data['record_data']
        
        # Validate record type
        if record_type not in StudentRecord.VALID_RECORD_TYPES:
            return jsonify({
                'success': False,
                'message': f'Invalid record type. Must be one of: {", ".join(StudentRecord.VALID_RECORD_TYPES)}',
                'error_code': 'INVALID_RECORD_TYPE'
            }), 400
        
        # Get current user
        current_user = get_current_user()
        
        # Create student record
        student_record = StudentRecord(
            student_id=student_id,
            record_type=record_type,
            raw_data=record_data
        )
        
        logger.info("Processing student record upload", 
                   extra={
                       "student_id": student_id,
                       "record_type": record_type,
                       "uploaded_by": current_user.username,
                       "correlation_id": getattr(g, 'correlation_id', 'unknown')
                   })
        
        # Process the record (mask -> encrypt -> hash)
        if not student_record.process_data(current_user.username):
            logger.error("Failed to process record data", 
                        extra={"student_id": student_id, "record_type": record_type})
            return jsonify({
                'success': False,
                'message': 'Failed to process record data',
                'error_code': 'RECORD_PROCESSING_FAILED'
            }), 500
        
        # Save to database
        if not student_record.save_to_database():
            logger.error("Failed to save record to database", 
                        extra={"student_id": student_id, "record_type": record_type})
            return jsonify({
                'success': False,
                'message': 'Failed to save record to database',
                'error_code': 'DATABASE_SAVE_FAILED'
            }), 500
        
        # Get blockchain and PBFT from singletons
        blockchain = get_blockchain()
        pbft_consensus = get_pbft_consensus()
        
        # Add to blockchain with PBFT consensus — isolated from DB save
        blockchain_success = False
        blockchain_error   = None
        try:
            blockchain_success = student_record.add_to_blockchain(blockchain, pbft_consensus)
            if blockchain_success:
                logger.info("Complete workflow successful",
                            extra={"student_id": student_id, "record_type": record_type,
                                   "data_hash": student_record.data_hash})
            else:
                logger.warning("Database saved but blockchain validation failed",
                               extra={"student_id": student_id})
        except BlockchainIntegrityError as bie:
            blockchain_error = str(bie)
            logger.error("Blockchain integrity error during upload",
                         extra={"error": blockchain_error, "student_id": student_id})
            # DB record is already saved — return 503 so caller knows chain is degraded
            return jsonify({
                'success': False,
                'message': 'Record saved to database but blockchain is currently unavailable.',
                'error_code': 'BLOCKCHAIN_UNAVAILABLE',
                'db_saved': True,
                'record_id': student_record.record_id,
                'detail': blockchain_error,
            }), 503
        
        # Log the upload
        db_manager = DatabaseManager()
        db_manager.log_access_attempt(
            student_id=student_id,
            accessor_username=current_user.username,
            record_id=student_record.record_id,
            action='UPLOAD_RECORD',
            access_granted=True,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        return jsonify({
            'success': True,
            'message': 'Student record uploaded successfully',
            'record_info': {
                'record_id': student_record.record_id,
                'student_id': student_id,
                'record_type': record_type,
                'data_hash': student_record.data_hash,
                'blockchain_verified': blockchain_success,
                'blockchain_hash': student_record.blockchain_hash,
                'created_by': current_user.username,
                'created_at': datetime.now().isoformat()
            },
            'blockchain_info': blockchain.get_chain_info(),
            'consensus_stats': pbft_consensus.get_consensus_stats()
        }), 201
        
    except Exception as e:
        logger.error("Upload record error", extra={"error": str(e), "traceback": traceback.format_exc()})
        return jsonify({
            'success': False,
            'message': 'Error uploading record',
            'error_code': 'UPLOAD_ERROR'
        }), 500

@record_bp.route('/view/<student_id>', methods=['GET'])
@login_required
def view_records(student_id):
    """
    View student records (with permission checks)
    
    Query parameters:
    - record_type: Filter by specific record type (optional)
    - masked: Return masked view (default: true for non-authorized users)
    """
    try:
        current_user = get_current_user()
        record_type = request.args.get('record_type')
        force_masked = request.args.get('masked', 'false').lower() == 'true'
        
        # Check access permissions
        if not current_user.can_access_record(student_id, record_type):
            # Log unauthorized access attempt
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id=student_id,
                accessor_username=current_user.username,
                record_id=None,
                action='UNAUTHORIZED_ACCESS_ATTEMPT',
                access_granted=False,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            return jsonify({
                'success': False,
                'message': 'Access denied. You do not have permission to view these records.',
                'error_code': 'ACCESS_DENIED',
                'student_id': student_id,
                'your_role': current_user.role
            }), 403
        
        # Get records
        records = StudentRecord.get_by_student_id(student_id, record_type)
        
        if not records:
            return jsonify({
                'success': True,
                'message': 'No records found',
                'records': [],
                'student_id': student_id,
                'record_type': record_type
            }), 200
        
        # Prepare response data
        records_data = []
        
        for record in records:
            # Log access
            db_manager = DatabaseManager()
            db_manager.log_access_attempt(
                student_id=student_id,
                accessor_username=current_user.username,
                record_id=record.record_id,
                action='VIEW_RECORD',
                access_granted=True,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            # Determine what level of data to return
            if force_masked or (current_user.role == 'verifier' and not current_user.can_access_record(student_id, record.record_type)):
                # Return masked view
                record_data = record.get_masked_view()
            elif current_user.role == 'admin' or (current_user.role == 'student' and current_user.student_id == student_id):
                # Return full decrypted data for admins and record owners
                record_data = record.to_dict(include_decrypted=True)
            else:
                # Return basic info with masked sensitive data
                record_data = record.to_dict()
            
            records_data.append(record_data)
        
        return jsonify({
            'success': True,
            'message': f'Retrieved {len(records)} record(s)',
            'records': records_data,
            'student_id': student_id,
            'record_type': record_type,
            'access_level': current_user.role,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error("View records error", extra={"error": str(e), "traceback": traceback.format_exc()})
        return jsonify({
            'success': False,
            'message': 'Error retrieving records',
            'error_code': 'VIEW_RECORDS_ERROR'
        }), 500

@record_bp.route('/verify/<student_id>/<record_id>', methods=['GET'])
@login_required
@role_required(['admin', 'verifier'])
def verify_record(student_id, record_id):
    """
    Verify authenticity of a specific record using blockchain
    
    This compares the stored hash with blockchain hash and validates integrity
    """
    try:
        current_user = get_current_user()
        
        # Get blockchain and PBFT from singletons
        blockchain = get_blockchain()
        pbft_consensus = get_pbft_consensus()
        
        # Check access permissions
        if current_user.role == 'verifier' and not current_user.can_access_record(student_id):
            return jsonify({
                'success': False,
                'message': 'Access denied for verification',
                'error_code': 'VERIFICATION_ACCESS_DENIED'
            }), 403
        
        # Get the specific record
        records = StudentRecord.get_by_student_id(student_id)
        record = next((r for r in records if r.record_id == int(record_id)), None)
        
        if not record:
            return jsonify({
                'success': False,
                'message': 'Record not found',
                'error_code': 'RECORD_NOT_FOUND'
            }), 404
        
        # Perform verification checks
        verification_results = {
            'record_info': {
                'record_id': record.record_id,
                'student_id': record.student_id,
                'record_type': record.record_type,
                'created_at': record.created_at,
                'is_verified': record.is_verified
            },
            'verification_checks': {}
        }
        
        # Check 1: Data integrity (hash verification)
        integrity_check = record.verify_integrity()
        verification_results['verification_checks']['data_integrity'] = {
            'passed': integrity_check,
            'description': 'Verifies that record data has not been tampered with'
        }
        
        # Check 2: Blockchain presence
        blockchain_check = False
        blockchain_block = None
        
        if record.blockchain_hash and record.data_hash:
            blockchain_block = blockchain.get_block_by_hash(record.data_hash)
            blockchain_check = blockchain_block is not None
        
        verification_results['verification_checks']['blockchain_presence'] = {
            'passed': blockchain_check,
            'description': 'Verifies that record hash exists in blockchain',
            'blockchain_hash': record.blockchain_hash
        }
        
        # Check 3: Blockchain integrity
        chain_validity = blockchain.is_chain_valid()
        verification_results['verification_checks']['blockchain_integrity'] = {
            'passed': chain_validity,
            'description': 'Verifies that blockchain chain is valid and unbroken'
        }
        
        # Check 4: Hash consistency
        hash_consistency = record.data_hash and record.blockchain_hash
        if blockchain_block:
            hash_consistency = hash_consistency and (record.data_hash == blockchain_block.data_hash)
        
        verification_results['verification_checks']['hash_consistency'] = {
            'passed': hash_consistency,
            'description': 'Verifies that database hash matches blockchain hash'
        }
        
        # Overall verification result
        all_checks_passed = all(
            check['passed'] for check in verification_results['verification_checks'].values()
        )
        
        verification_results['overall_verification'] = {
            'is_authentic': all_checks_passed,
            'confidence_level': 'high' if all_checks_passed else 'low',
            'verified_at': datetime.now().isoformat(),
            'verified_by': current_user.username
        }
        
        # Add blockchain info
        verification_results['blockchain_info'] = blockchain.get_chain_info()
        
        # Log verification attempt
        db_manager = DatabaseManager()
        db_manager.log_access_attempt(
            student_id=student_id,
            accessor_username=current_user.username,
            record_id=record.record_id,
            action='VERIFY_RECORD',
            access_granted=True,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        return jsonify({
            'success': True,
            'message': 'Record verification completed',
            'verification_results': verification_results
        }), 200
        
    except Exception as e:
        logger.error("Verify record error", extra={"error": str(e), "traceback": traceback.format_exc()})
        return jsonify({
            'success': False,
            'message': 'Error during record verification',
            'error_code': 'VERIFICATION_ERROR'
        }), 500

@record_bp.route('/blockchain/info', methods=['GET'])
@login_required
@role_required(['admin', 'verifier'])
def blockchain_info():
    """
    Get blockchain information and statistics
    """
    try:
        # Get blockchain and PBFT from singletons
        blockchain = get_blockchain()
        pbft_consensus = get_pbft_consensus()
        
        chain_info = blockchain.get_chain_info()
        consensus_stats = pbft_consensus.get_consensus_stats()
        
        # Add recent blocks info (last 5 blocks)
        recent_blocks = []
        chain_length = len(blockchain.chain)
        start_index = max(0, chain_length - 5)
        
        for i in range(start_index, chain_length):
            block = blockchain.chain[i]
            recent_blocks.append(block.to_dict())
        
        return jsonify({
            'success': True,
            'blockchain_info': chain_info,
            'consensus_stats': consensus_stats,
            'recent_blocks': recent_blocks,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error("Blockchain info error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error retrieving blockchain information',
            'error_code': 'BLOCKCHAIN_INFO_ERROR'
        }), 500

@record_bp.route('/statistics', methods=['GET'])
@login_required
@role_required(['admin'])
def get_statistics():
    """
    Get system statistics (admin only)
    """
    try:
        # Get blockchain and PBFT from singletons
        blockchain = get_blockchain()
        pbft_consensus = get_pbft_consensus()
        
        db_manager = DatabaseManager()
        db_stats = db_manager.get_database_stats()
        
        blockchain_stats = blockchain.get_chain_info()
        consensus_stats = pbft_consensus.get_consensus_stats()
        
        return jsonify({
            'success': True,
            'statistics': {
                'database': db_stats,
                'blockchain': blockchain_stats,
                'consensus': consensus_stats,
                'system': {
                    'generated_at': datetime.now().isoformat(),
                    'uptime': 'N/A'  # Could add actual uptime tracking
                }
            }
        }), 200
        
    except Exception as e:
        logger.error("Statistics error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error retrieving statistics',
            'error_code': 'STATISTICS_ERROR'
        }), 500

@record_bp.route('/search', methods=['POST'])
@login_required
@role_required(['admin'])
def search_records():
    """
    Search for records by various criteria (admin only)
    
    Expected JSON:
    {
        "criteria": {
            "student_id": "string" (optional),
            "record_type": "string" (optional),
            "date_from": "ISO date" (optional),
            "date_to": "ISO date" (optional),
            "created_by": "string" (optional)
        }
    }
    """
    try:
        data = request.get_json()
        criteria = data.get('criteria', {})

        db_manager = DatabaseManager()
        results = db_manager.search_student_records(
            student_id  = criteria.get('student_id'),
            record_type = criteria.get('record_type'),
            created_by  = criteria.get('created_by'),
            date_from   = criteria.get('date_from'),
            date_to     = criteria.get('date_to'),
        )

        # Convert datetime objects to ISO strings for JSON serialisation
        serialisable = []
        for row in results:
            row_copy = dict(row)
            for key, val in row_copy.items():
                if hasattr(val, 'isoformat'):
                    row_copy[key] = val.isoformat()
            serialisable.append(row_copy)

        return jsonify({
            'success': True,
            'message': 'Search completed',
            'results': serialisable,
            'found_count': len(serialisable),
            'search_criteria': criteria,
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        logger.error("Search error", extra={"error": str(e)})
        return jsonify({
            'success': False,
            'message': 'Error performing search',
            'error_code': 'SEARCH_ERROR'
        }), 500