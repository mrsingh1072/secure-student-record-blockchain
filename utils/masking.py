"""
Data masking utilities for protecting sensitive information in student records
"""

import re
import random
from datetime import datetime, timedelta

class DataMasking:
    """
    Handles masking of sensitive data in student records for display and logging
    """
    
    # Define sensitive fields that should be masked
    SENSITIVE_FIELDS = {
        'personal': [
            'student_id', 'social_security_number', 'ssn', 'national_id',
            'phone_number', 'mobile', 'address', 'email', 'parent_email',
            'emergency_contact', 'date_of_birth', 'dob', 'birth_date'
        ],
        'academic': [
            'grades', 'grade_points', 'detailed_grades', 'individual_scores',
            'disciplinary_actions', 'counselor_notes', 'special_needs'
        ],
        'financial': [
            'tuition_fees', 'scholarship_amount', 'financial_aid',
            'payment_history', 'outstanding_balance', 'bank_details'
        ]
    }
    
    # Masking patterns
    MASKING_PATTERNS = {
        'full': '*****',
        'partial_start': lambda x: '*' * (len(x) - 4) + x[-4:] if len(x) > 4 else '*' * len(x),
        'partial_middle': lambda x: x[:2] + '*' * (len(x) - 4) + x[-2:] if len(x) > 4 else '*' * len(x),
        'email': lambda x: x.split('@')[0][:2] + '***@' + x.split('@')[1] if '@' in x else '*****',
        'phone': lambda x: re.sub(r'\d', '*', x[:-4]) + x[-4:] if len(x) > 4 else '*' * len(x),
        'date': lambda x: 'YYYY-MM-DD',
        'numeric_range': lambda x: f"Range: {x//10*10}-{x//10*10+9}" if isinstance(x, (int, float)) else "***"
    }
    
    def __init__(self, masking_level='medium'):
        """
        Initialize data masking utility
        
        Args:
            masking_level (str): Level of masking ('low', 'medium', 'high')
        """
        self.masking_level = masking_level
        self.masking_config = self._get_masking_config()
    
    def _get_masking_config(self):
        """
        Get masking configuration based on level
        
        Returns:
            dict: Masking configuration
        """
        configs = {
            'low': {
                'mask_personal': True,
                'mask_academic': False,
                'mask_financial': True,
                'show_partial': True,
                'mask_metadata': False
            },
            'medium': {
                'mask_personal': True,
                'mask_academic': True,
                'mask_financial': True,
                'show_partial': True,
                'mask_metadata': True
            },
            'high': {
                'mask_personal': True,
                'mask_academic': True,
                'mask_financial': True,
                'show_partial': False,
                'mask_metadata': True
            }
        }
        
        return configs.get(self.masking_level, configs['medium'])
    
    def mask_sensitive_data(self, data, record_type='general'):
        """
        Main function to mask sensitive data in student records
        
        Args:
            data (dict): Student record data
            record_type (str): Type of record for context-specific masking
            
        Returns:
            dict: Masked version of data
        """
        if not isinstance(data, dict):
            return data
        
        masked_data = {}
        
        for key, value in data.items():
            masked_data[key] = self._mask_field(key, value, record_type)
        
        # Add masking metadata
        if self.masking_config['mask_metadata']:
            masked_data['_masking_info'] = {
                'masked_at': datetime.now().isoformat(),
                'masking_level': self.masking_level,
                'record_type': record_type,
                'original_fields_count': len(data)
            }
        
        return masked_data
    
    def _mask_field(self, field_name, value, record_type):
        """
        Mask individual field based on sensitivity and type
        
        Args:
            field_name (str): Name of the field
            value: Value to potentially mask
            record_type (str): Type of record
            
        Returns:
            Masked value
        """
        field_lower = field_name.lower()
        
        # Check if field is in sensitive categories
        is_personal = any(sensitive in field_lower for sensitive in self.SENSITIVE_FIELDS['personal'])
        is_academic = any(sensitive in field_lower for sensitive in self.SENSITIVE_FIELDS['academic'])
        is_financial = any(sensitive in field_lower for sensitive in self.SENSITIVE_FIELDS['financial'])
        
        # Apply masking based on configuration and field type
        if is_personal and self.masking_config['mask_personal']:
            return self._apply_masking_pattern(field_name, value, 'personal')
        elif is_academic and self.masking_config['mask_academic']:
            return self._apply_masking_pattern(field_name, value, 'academic')
        elif is_financial and self.masking_config['mask_financial']:
            return self._apply_masking_pattern(field_name, value, 'financial')
        
        # Handle nested dictionaries and lists
        if isinstance(value, dict):
            return self.mask_sensitive_data(value, record_type)
        elif isinstance(value, list):
            return [self.mask_sensitive_data(item, record_type) if isinstance(item, dict) else item for item in value]
        
        return value
    
    def _apply_masking_pattern(self, field_name, value, category):
        """
        Apply appropriate masking pattern based on field type
        
        Args:
            field_name (str): Name of the field
            value: Value to mask
            category (str): Category of sensitive data
            
        Returns:
            Masked value
        """
        if value is None:
            return None
        
        field_lower = field_name.lower()
        str_value = str(value)
        
        # Email masking
        if 'email' in field_lower:
            return self.MASKING_PATTERNS['email'](str_value)
        
        # Phone number masking
        elif any(phone in field_lower for phone in ['phone', 'mobile', 'contact']):
            return self.MASKING_PATTERNS['phone'](str_value)
        
        # Date masking
        elif any(date in field_lower for date in ['date', 'birth', 'dob']):
            return self.MASKING_PATTERNS['date'](str_value)
        
        # Student ID / SSN masking
        elif any(id_field in field_lower for id_field in ['student_id', 'ssn', 'national_id']):
            if self.masking_config['show_partial']:
                return self.MASKING_PATTERNS['partial_start'](str_value)
            else:
                return self.MASKING_PATTERNS['full']
        
        # Numeric grades/scores
        elif isinstance(value, (int, float)) and category == 'academic':
            if 'gpa' in field_lower or 'grade' in field_lower:
                return self.MASKING_PATTERNS['numeric_range'](value)
        
        # Financial amounts
        elif isinstance(value, (int, float)) and category == 'financial':
            return self.MASKING_PATTERNS['numeric_range'](value)
        
        # Address masking
        elif 'address' in field_lower:
            if self.masking_config['show_partial']:
                return self.MASKING_PATTERNS['partial_middle'](str_value)
            else:
                return self.MASKING_PATTERNS['full']
        
        # Default masking for other sensitive fields
        else:
            if self.masking_config['show_partial'] and len(str_value) > 6:
                return self.MASKING_PATTERNS['partial_middle'](str_value)
            else:
                return self.MASKING_PATTERNS['full']
    
    def mask_grades(self, grades_data):
        """
        Specifically mask grades and academic performance data
        
        Args:
            grades_data (dict or list): Grades data structure
            
        Returns:
            Masked grades data
        """
        if isinstance(grades_data, list):
            return [self.mask_grades(grade) for grade in grades_data]
        
        if isinstance(grades_data, dict):
            masked_grades = {}
            for key, value in grades_data.items():
                if key.lower() in ['grade', 'score', 'points', 'marks']:
                    if isinstance(value, (int, float)):
                        masked_grades[key] = self.MASKING_PATTERNS['numeric_range'](value)
                    else:
                        masked_grades[key] = "***"
                else:
                    masked_grades[key] = value
            return masked_grades
        
        return grades_data
    
    def create_summary_view(self, data, record_type='general'):
        """
        Create a summary view with minimal sensitive information
        
        Args:
            data (dict): Original record data
            record_type (str): Type of record
            
        Returns:
            dict: Summary view with reduced sensitive data
        """
        if not isinstance(data, dict):
            return data
        
        # Define fields to include in summary
        summary_fields = {
            'transcript': ['student_name', 'institution', 'program', 'semester', 'total_credits'],
            'certificate': ['student_name', 'certificate_name', 'institution', 'issued_date'],
            'diploma': ['student_name', 'degree_name', 'institution', 'graduation_date'],
            'grade_card': ['student_name', 'institution', 'semester', 'academic_year'],
            'general': ['student_name', 'institution', 'record_type']
        }
        
        allowed_fields = summary_fields.get(record_type, summary_fields['general'])
        
        summary = {}
        for field in allowed_fields:
            if field in data:
                # Apply light masking to even summary fields
                if field == 'student_name':
                    name_parts = str(data[field]).split()
                    if len(name_parts) > 1:
                        summary[field] = f"{name_parts[0]} {name_parts[-1][0]}***"
                    else:
                        summary[field] = f"{name_parts[0][:2]}***"
                else:
                    summary[field] = data[field]
        
        summary['_summary'] = True
        summary['_masked_fields_count'] = len(data) - len(summary) + 1
        
        return summary
    
    def generate_audit_log_data(self, original_data, masked_data):
        """
        Generate audit log information about masking operation
        
        Args:
            original_data (dict): Original data
            masked_data (dict): Masked data
            
        Returns:
            dict: Audit log information
        """
        masked_fields = []
        
        for key in original_data.keys():
            if key in masked_data:
                original_value = str(original_data[key])
                masked_value = str(masked_data[key])
                if original_value != masked_value:
                    masked_fields.append({
                        'field': key,
                        'original_length': len(original_value),
                        'masked_pattern': self._detect_pattern(masked_value)
                    })
        
        return {
            'timestamp': datetime.now().isoformat(),
            'masking_level': self.masking_level,
            'total_fields': len(original_data),
            'masked_fields_count': len(masked_fields),
            'masked_fields': masked_fields
        }
    
    def _detect_pattern(self, masked_value):
        """
        Detect which masking pattern was applied
        
        Args:
            masked_value (str): Masked value
            
        Returns:
            str: Detected pattern type
        """
        if '*****' in masked_value:
            return 'full_mask'
        elif '***@' in masked_value:
            return 'email_mask'
        elif 'Range:' in masked_value:
            return 'numeric_range'
        elif 'YYYY-MM-DD' in masked_value:
            return 'date_mask'
        elif '*' in masked_value:
            return 'partial_mask'
        else:
            return 'no_mask'
    
    def unmask_authorized_fields(self, masked_data, authorized_fields, original_data):
        """
        Unmask specific fields for authorized users
        
        Args:
            masked_data (dict): Masked data
            authorized_fields (list): List of fields user is authorized to see
            original_data (dict): Original unmasked data
            
        Returns:
            dict: Data with authorized fields unmasked
        """
        result = masked_data.copy()
        
        for field in authorized_fields:
            if field in original_data:
                result[field] = original_data[field]
        
        # Add authorization metadata
        result['_authorization_info'] = {
            'unmasked_fields': authorized_fields,
            'unmasked_at': datetime.now().isoformat()
        }
        
        return result
    
    def get_masking_stats(self):
        """
        Get statistics about masking configuration
        
        Returns:
            dict: Masking statistics
        """
        return {
            'masking_level': self.masking_level,
            'config': self.masking_config,
            'sensitive_field_categories': len(self.SENSITIVE_FIELDS),
            'total_sensitive_fields': sum(len(fields) for fields in self.SENSITIVE_FIELDS.values()),
            'available_patterns': list(self.MASKING_PATTERNS.keys())
        }

# Utility functions for direct use
def quick_mask(data, level='medium'):
    """
    Quick masking function
    
    Args:
        data (dict): Data to mask
        level (str): Masking level
        
    Returns:
        dict: Masked data
    """
    masking = DataMasking(level)
    return masking.mask_sensitive_data(data)

def mask_student_id(student_id, show_last=4):
    """
    Quick student ID masking
    
    Args:
        student_id (str): Student ID to mask
        show_last (int): Number of characters to show at end
        
    Returns:
        str: Masked student ID
    """
    if len(student_id) <= show_last:
        return '*' * len(student_id)
    return '*' * (len(student_id) - show_last) + student_id[-show_last:]

def mask_email(email):
    """
    Quick email masking
    
    Args:
        email (str): Email to mask
        
    Returns:
        str: Masked email
    """
    if '@' not in email:
        return '*****'
    username, domain = email.split('@', 1)
    masked_username = username[:2] + '*' * (len(username) - 2)
    return f"{masked_username}@{domain}"