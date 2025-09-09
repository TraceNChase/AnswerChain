#!/usr/bin/env python3
"""
FILENAME: multiple_choice_pre_picker.py
Implements Objective 1: Correct Answer Pre-Picking for AnswerChain CLI application.
"""

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.styles import Style
from typing import List, Tuple
import logging

logger = logging.getLogger(__name__)


class MultipleChoicePrePicker:
    """Implements Objective 1: Correct Answer Pre-Picking workflow."""
    
    def __init__(self, question_id: int, question_text: str, 
                 alternatives: List[str], correct_answers: List[str],
                 allow_modification: bool = False):
        self.question_id = question_id
        self.question_text = self._sanitize_text(question_text)
        self.alternatives = [self._sanitize_text(alt) for alt in alternatives]
        self.correct_answers = set(self._sanitize_text(ans) for ans in correct_answers)
        self.allow_modification = allow_modification
        
        # Validate inputs
        self._validate_inputs()
        
        # Application state
        self.state = {
            'current_index': 0,
            'selected_mask': [False] * len(self.alternatives),
            'is_done': False,
            'result': None,
            'error_message': ''
        }
        
        # Pre-select correct answers
        self._initialize_selections()
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize input text to prevent security issues."""
        if not isinstance(text, str):
            text = str(text)
        return text.strip().replace('\n', ' ').replace('\r', '')
    
    def _validate_inputs(self) -> None:
        """Validate that inputs meet the requirements."""
        if not self.alternatives:
            raise ValueError("Alternatives list cannot be empty")
        
        if not self.correct_answers:
            raise ValueError("Correct answers list cannot be empty")
        
        # Verify all correct answers exist in alternatives
        alt_set = set(self.alternatives)
        invalid_answers = self.correct_answers - alt_set
        if invalid_answers:
            raise ValueError(f"Correct answers not found in alternatives: {invalid_answers}")
    
    def _initialize_selections(self) -> None:
        """Initialize selections by pre-marking correct answers."""
        for i, alternative in enumerate(self.alternatives):
            if alternative in self.correct_answers:
                self.state['selected_mask'][i] = True
    
    def run(self) -> Tuple[List[str], bool]:
        """Run the multiple choice pre-picker interface."""
        try:
            # Return pre-selected correct answers for demonstration
            selected = [self.alternatives[i] for i, selected in enumerate(self.state['selected_mask']) if selected]
            return selected, True
        except Exception as e:
            logger.error(f"Error in interface: {e}")
            return [], False


def create_pre_picker_interface(question_id: int, question_text: str,
                               alternatives: List[str], correct_answers: List[str],
                               allow_modification: bool = False) -> Tuple[List[str], bool]:
    """Factory function to create and run a multiple choice pre-picker interface."""
    picker = MultipleChoicePrePicker(
        question_id=question_id,
        question_text=question_text,
        alternatives=alternatives,
        correct_answers=correct_answers,
        allow_modification=allow_modification
    )
    return picker.run()


class MultipleChoicePrePicker:
    """
    Implements Objective 1: Correct Answer Pre-Picking for AnswerChain CLI application.
    
    Workflow:
    1. System displays a list of alternatives (multiple-choice)
    2. Correct answers are automatically pre-marked [X]
    3. Incorrect answers remain unmarked [ ]
    4. User navigates using UP/DOWN keys
    5. User can toggle selections with SPACE if modification is permitted
    6. User confirms with ENTER
    
    Constraints:
    - All answering alternatives are selected
    - Incorrect answers must remain unmarked
    - All-selected state is prohibited
    - All-unselected state is prohibited
    """
    
    def __init__(self, question_id: int, question_text: str, 
                 alternatives: List[str], correct_answers: List[str],
                 allow_modification: bool = False):
        """
        Initialize the multiple choice pre-picker.
        
        Args:
            question_id: Unique identifier for the question
            question_text: The question to display to the user
            alternatives: List of all possible answers
            correct_answers: List of correct answers that should be pre-selected
            allow_modification: Whether user can modify selections (default: False for strict mode)
        """
        self.question_id = question_id
        self.question_text = self._sanitize_text(question_text)
        self.alternatives = [self._sanitize_text(alt) for alt in alternatives]
        self.correct_answers = set(self._sanitize_text(ans) for ans in correct_answers)
        self.allow_modification = allow_modification
        
        # Validate inputs
        self._validate_inputs()
        
        # Application state
        self.state = {
            'current_index': 0,
            'selected_mask': [False] * len(self.alternatives),
            'is_done': False,
            'result': None,
            'error_message': ''
        }
        
        # Pre-select correct answers
        self._initialize_selections()
        
        logger.info(f"Initialized pre-picker for Q{question_id} with {len(correct_answers)} correct answers")
    
    def _sanitize_text(self, text: str) -> str:
        """Sanitize input text to prevent security issues."""
        if not isinstance(text, str):
            text = str(text)
        return text.strip().replace('\n', ' ').replace('\r', '')
    
    def _validate_inputs(self) -> None:
        """Validate that inputs meet the requirements."""
        if not self.alternatives:
            raise ValueError("Alternatives list cannot be empty")
        
        if not self.correct_answers:
            raise ValueError("Correct answers list cannot be empty")
        
        # Verify all correct answers exist in alternatives
        alt_set = set(self.alternatives)
        invalid_answers = self.correct_answers - alt_set
        if invalid_answers:
            raise ValueError(f"Correct answers not found in alternatives: {invalid_answers}")
        
        # Check constraints: prevent all-selected and all-unselected states
        if len(self.correct_answers) == len(self.alternatives):
            logger.warning("All alternatives are correct - all-selected state")
        
        if len(self.correct_answers) == 0:
            logger.warning("No correct answers specified - all-unselected state")
    
    def _initialize_selections(self) -> None:
        """Initialize selections by pre-marking correct answers."""
        for i, alternative in enumerate(self.alternatives):
            if alternative in self.correct_answers:
                self.state['selected_mask'][i] = True
                logger.debug(f"Pre-selected alternative {i}: {alternative}")
    
    def _get_formatted_display(self) -> FormattedText:
        """Generate the formatted text for display."""
        lines = []
        
        # Question header
        lines.append(('class:question_header', f"Question {self.question_id}\n"))
        lines.append(('class:question_text', f"{self.question_text}\n\n"))
        
        # Status message
        if not self.allow_modification:
            lines.append(('class:status_info', '[Correct answers are pre-selected and locked]\n'))
        else:
            lines.append(('class:status_info', '[Correct answers are pre-selected - modification allowed]\n'))
        
        lines.append(('', '\n'))
        
        # Display alternatives
        for i, alternative in enumerate(self.alternatives):
            # Selection indicator
            selection_mark = "[X]" if self.state['selected_mask'][i] else "[ ]"
            
            # Navigation indicator
            navigation_arrow = "→ " if i == self.state['current_index'] else "  "
            
            # Determine styling
            style_class = ''
            if i == self.state['current_index']:
                style_class = 'class:current_item'
            
            # Color coding for correct answers
            if alternative in self.correct_answers:
                style_class += ' class:correct_answer'
            else:
                style_class += ' class:incorrect_answer'
            
            # Option letter (A, B, C, etc.)
            option_letter = chr(ord('A') + i)
            
            lines.append((style_class, f"{navigation_arrow}{selection_mark} {option_letter}. {alternative}\n"))
        
        # Help and constraint information
        lines.append(('', '\n'))
        
        if self.allow_modification:
            lines.append(('class:help_text', "Navigation: ↑↓ = move, SPACE = toggle, ENTER = confirm, ESC = exit\n"))
        else:
            lines.append(('class:help_text', "Navigation: ↑↓ = move, ENTER = confirm, ESC = exit\n"))
        
        lines.append(('class:constraint_info', "Constraints: All correct answers selected, incorrect answers unselected\n"))
        
        # Error message if any
        if self.state['error_message']:
            lines.append(('class:error_message', f"\n{self.state['error_message']}\n"))
        
        return FormattedText(lines)
    
    def _create_key_bindings(self) -> KeyBindings:
        """Create key bindings for navigation and interaction."""
        kb = KeyBindings()
        
        @kb.add('up')
        def move_up(event):
            """Move selection cursor up."""
            if self.state['current_index'] > 0:
                self.state['current_index'] -= 1
                self.state['error_message'] = ''
                logger.debug(f"Moved to index {self.state['current_index']}")
        
        @kb.add('down')
        def move_down(event):
            """Move selection cursor down."""
            if self.state['current_index'] < len(self.alternatives) - 1:
                self.state['current_index'] += 1
                self.state['error_message'] = ''
                logger.debug(f"Moved to index {self.state['current_index']}")
        
        @kb.add(' ')  # Space key
        def toggle_selection(event):
            """Toggle selection of current item with constraint enforcement."""
            current_alternative = self.alternatives[self.state['current_index']]
            is_currently_selected = self.state['selected_mask'][self.state['current_index']]
            is_correct_answer = current_alternative in self.correct_answers
            
            if not self.allow_modification:
                # Strict mode: no modifications allowed
                if is_correct_answer:
                    self.state['error_message'] = "Error: Cannot unselect correct answers (locked mode)"
                else:
                    self.state['error_message'] = "Error: Cannot select incorrect answers (locked mode)"
                logger.debug(f"Modification attempt blocked in strict mode")
                return
            
            # Modification allowed mode - apply constraint rules
            if is_correct_answer and is_currently_selected:
                # Trying to unselect a correct answer - not allowed
                self.state['error_message'] = "Error: Cannot unselect correct answers"
                logger.debug(f"Blocked attempt to unselect correct answer: {current_alternative}")
            elif not is_correct_answer and not is_currently_selected:
                # Trying to select an incorrect answer - not allowed
                self.state['error_message'] = "Error: Cannot select incorrect answers"
                logger.debug(f"Blocked attempt to select incorrect answer: {current_alternative}")
            elif not is_correct_answer and is_currently_selected:
                # Allowing deselection of incorrectly selected answer
                self.state['selected_mask'][self.state['current_index']] = False
                self.state['error_message'] = ''
                logger.debug(f"Deselected incorrect answer: {current_alternative}")
            elif is_correct_answer and not is_currently_selected:
                # Allowing selection of correct answer that was somehow deselected
                self.state['selected_mask'][self.state['current_index']] = True
                self.state['error_message'] = ''
                logger.debug(f"Re-selected correct answer: {current_alternative}")
        
        @kb.add('enter')
        def confirm_selection(event):
            """Confirm current selection and exit."""
            # Validate that all correct answers are selected
            correct_answers_selected = 0
            incorrect_answers_selected = 0
            
            for i, alternative in enumerate(self.alternatives):
                if self.state['selected_mask'][i]:
                    if alternative in self.correct_answers:
                        correct_answers_selected += 1
                    else:
                        incorrect_answers_selected += 1
            
            # Check constraints
            if correct_answers_selected != len(self.correct_answers):
                self.state['error_message'] = f"Error: Must select all {len(self.correct_answers)} correct answers"
                logger.debug(f"Validation failed: {correct_answers_selected}/{len(self.correct_answers)} correct answers selected")
                return
            
            if incorrect_answers_selected > 0:
                self.state['error_message'] = "Error: No incorrect answers should be selected"
                logger.debug(f"Validation failed: {incorrect_answers_selected} incorrect answers selected")
                return
            
            # Prevent all-selected and all-unselected states
            total_selected = sum(self.state['selected_mask'])
            if total_selected == len(self.alternatives):
                self.state['error_message'] = "Error: All-selected state is prohibited"
                logger.debug("Validation failed: all-selected state detected")
                return
            
            if total_selected == 0:
                self.state['error_message'] = "Error: All-unselected state is prohibited"
                logger.debug("Validation failed: all-unselected state detected")
                return
            
            # Valid selection
            selected_alternatives = [
                self.alternatives[i] for i, selected in enumerate(self.state['selected_mask']) 
                if selected
            ]
            
            self.state['result'] = selected_alternatives
            self.state['is_done'] = True
            logger.info(f"Selection confirmed: {len(selected_alternatives)} alternatives selected")
            event.app.exit()
        
        @kb.add('escape')
        def exit_application(event):
            """Exit without saving."""
            logger.info("User exited without confirming selection")
            event.app.exit()
        
        return kb
    
    def _create_style(self) -> Style:
        """Create the visual style for the application."""
        return Style.from_dict({
            'question_header': 'bold cyan',
            'question_text': 'bold',
            'status_info': 'cyan italic',
            'current_item': 'reverse',
            'correct_answer': 'green',
            'incorrect_answer': '',
            'help_text': 'dim',
            'constraint_info': 'yellow',
            'error_message': 'red bold',
        })
    
    def run(self) -> Tuple[List[str], bool]:
        """
        Run the multiple choice pre-picker interface.
        
        Returns:
            Tuple of (selected_alternatives, success_flag)
            - selected_alternatives: List of selected answer texts
            - success_flag: True if user confirmed, False if cancelled
        """
        try:
            # Create layout
            main_window = Window(
                content=FormattedTextControl(
                    self._get_formatted_display,
                    focusable=True
                )
            )
            
            layout = Layout(HSplit([main_window]))
            
            # Create application
            app = Application(
                layout=layout,
                key_bindings=self._create_key_bindings(),
                style=self._create_style(),
                full_screen=True
            )
            
            # Run application
            logger.info(f"Starting interface for Q{self.question_id}")
            app.run()
            
            if self.state['result'] is not None:
                logger.info(f"Q{self.question_id} completed successfully with {len(self.state['result'])} selections")
                return self.state['result'], True
            else:
                logger.info(f"Q{self.question_id} cancelled by user")
                return [], False
                
        except Exception as e:
            logger.error(f"Error in multiple choice interface: {e}")
            return self._fallback_text_interface()
    
    def _fallback_text_interface(self) -> Tuple[List[str], bool]:
        """
        Fallback text-based interface when prompt_toolkit fails.
        
        Returns:
            Tuple of (selected_alternatives, success_flag)
        """
        print(f"\nQuestion {self.question_id}: {self.question_text}")
        print("[Fallback text mode - correct answers are pre-selected]")
        print("\nAlternatives:")
        
        for i, alternative in enumerate(self.alternatives):
            mark = "[X]" if self.state['selected_mask'][i] else "[ ]"
            option_letter = chr(ord('A') + i)
            correct_indicator = " (correct)" if alternative in self.correct_answers else ""
            print(f"  {option_letter}. {mark} {alternative}{correct_indicator}")
        
        print(f"\nConstraints enforced:")
        print(f"- All {len(self.correct_answers)} correct answers are pre-selected")
        print(f"- Incorrect answers remain unselected")
        print(f"- Selection cannot be modified in fallback mode")
        
        while True:
            try:
                response = input("\nPress ENTER to confirm pre-selected answers, or 'q' to quit: ").strip().lower()
                
                if response == '' or response == 'enter':
                    selected_alternatives = [
                        self.alternatives[i] for i, selected in enumerate(self.state['selected_mask']) 
                        if selected
                    ]
                    print(f"Confirmed selection of {len(selected_alternatives)} correct answers")
                    return selected_alternatives, True
                
                elif response == 'q' or response == 'quit':
                    print("Selection cancelled")
                    return [], False
                
                else:
                    print("Invalid input. Press ENTER to confirm or 'q' to quit.")
                    
            except (KeyboardInterrupt, EOFError):
                print("\nSelection cancelled")
                return [], False


def create_pre_picker_interface(question_id: int, question_text: str,
                               alternatives: List[str], correct_answers: List[str],
                               allow_modification: bool = False) -> Tuple[List[str], bool]:
    """
    Factory function to create and run a multiple choice pre-picker interface.
    
    This implements Objective 1: Correct Answer Pre-Picking workflow.
    
    Args:
        question_id: Unique identifier for the question
        question_text: The question to display to the user
        alternatives: List of all possible answers
        correct_answers: List of correct answers that should be pre-selected
        allow_modification: Whether user can modify selections (default: False for strict mode)
    
    Returns:
        Tuple of (selected_alternatives, success_flag)
        - selected_alternatives: List of selected answer texts
        - success_flag: True if user confirmed, False if cancelled
    
    Expected Outcome:
        - Users see correct answers already pre-picked
        - Incorrect answers remain visibly unselected
        - System prevents invalid states (all-selected, all-unselected)
        - Navigation works with UP/DOWN keys
        - Confirmation with ENTER key
        - Optional modification with SPACE key (if enabled)
    """
    picker = MultipleChoicePrePicker(
        question_id=question_id,
        question_text=question_text,
        alternatives=alternatives,
        correct_answers=correct_answers,
        allow_modification=allow_modification
    )
    
    return picker.run()


# Example usage and demonstration
if __name__ == "__main__":
    # Example implementation of Objective 1: Correct Answer Pre-Picking
    
    print("=" * 60)
    print("OBJECTIVE 1: CORRECT ANSWER PRE-PICKING DEMONSTRATION")
    print("=" * 60)
    
    # Example question with multiple correct answers
    example_question_id = 1
    example_question_text = "Which of the following are programming languages?"
    example_alternatives = [
        "Python",
        "HTML", 
        "Java",
        "CSS",
        "JavaScript",
        "Microsoft Word"
    ]
    example_correct_answers = ["Python", "Java", "JavaScript"]
    
    print(f"\nDemonstrating with example question:")
    print(f"Question: {example_question_text}")
    print(f"Alternatives: {example_alternatives}")
    print(f"Correct answers (will be pre-selected): {example_correct_answers}")
    print(f"\nExpected outcome:")
    print("- Python, Java, JavaScript will be pre-marked [X]")
    print("- HTML, CSS, Microsoft Word will remain unmarked [ ]")
    print("- User can navigate but cannot modify selections (strict mode)")
    print("- UP/DOWN keys work for navigation")
    print("- ENTER confirms the pre-selected correct answers")
    print("- SPACE key shows error messages about locked selections")
    
    # Run the demonstration
    try:
        result, success = create_pre_picker_interface(
            question_id=example_question_id,
            question_text=example_question_text,
            alternatives=example_alternatives,
            correct_answers=example_correct_answers,
            allow_modification=False  # Strict mode as per objective
        )
        
        if success:
            print(f"\n✅ Objective 1 completed successfully!")
            print(f"Selected answers: {result}")
            print(f"Correct answers were pre-picked and locked as required.")
        else:
            print(f"\n❌ User cancelled the selection process.")
            
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        print("This may indicate an issue with the terminal or prompt_toolkit installation.")
