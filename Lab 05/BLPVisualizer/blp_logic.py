class BLPSystem:

    LEVELS = {"U": 0, "C": 1, "S": 2, "TS": 3}

    def __init__(self):
        self.subjects = {}
        self.objects = {}

    def add_subject(self, name, max_level, start_level):
        if self.LEVELS[start_level] > self.LEVELS[max_level]:
            raise ValueError("Start level cannot be higher than max level.")
        self.subjects[name] = {"curr": start_level, "max": max_level}

    def add_object(self, name, level):
        self.objects[name] = level

    def validate_levels(self, subject, obj):
        subject_level = self.LEVELS[self.subjects[subject]["curr"]]
        object_level = self.LEVELS[self.objects[obj]]

        if(subject_level == object_level):
            return True
        return False
    
    def set_level(self, subject, new_level):
        subject_curr_level = self.LEVELS[self.subjects[subject]["curr"]]
        subject_max_level = self.LEVELS[self.subjects[subject]["max"]]

        if subject_curr_level < self.LEVELS[new_level] and self.LEVELS[new_level] <= subject_max_level:
            self.subjects[subject]["curr"] = new_level
            return f"Subject {subject} level raised to {new_level}."
        return f"Cannot lower below current level and cannot raise above max level."

    def read(self, subject, obj):
        subject_name = subject
        subject_curr_level = self.LEVELS[self.subjects[subject]["curr"]]
        subject_max_level = self.LEVELS[self.subjects[subject]["max"]]
        object_level = self.LEVELS[self.objects[obj]]

        if(self.validate_levels(subject, obj)):
            print(f" ALLOW: Obj lvl ({self.objects[obj]}) <= Subj Max ({self.subjects[subject]["max"]})")
            #print(f"ALLOW: {subject_name} READ {obj}")
        elif object_level > subject_curr_level:
            if object_level <= subject_max_level:
                print(f" ALLOW: Obj lvl ({self.objects[obj]}) <= Subj Max ({self.subjects[subject]["max"]})")
                print(f"INFO: Raising {subject_name}'s current level to {self.objects[obj]}.")
                self.set_level(subject, self.objects[obj])
                #print(f"ALLOW: {subject_name} READ {obj}")
            else:
                print(f" DENY: Obj lvl ({self.objects[obj]}) > Subj Max ({self.subjects[subject]["max"]}) [No Read Up].")

    def write(self, subject, obj):
        subject_name = subject
        subject_curr_level = self.LEVELS[self.subjects[subject]["curr"]]
        object_level = self.LEVELS[self.objects[obj]]

        if(self.validate_levels(subject, obj)):
            print(f" ALLOW: Subj lvl ({self.subjects[subject]["curr"]}) <= Obj lvl ({self.objects[obj]})")
            #print(f"ALLOW: {subject_name} WRITE {obj}")
        elif subject_curr_level <= object_level:
                print(f" ALLOW: Subj lvl ({self.subjects[subject]["curr"]}) <= Obj lvl ({self.objects[obj]})")
                #print(f"ALLOW: {subject_name} WRITE {obj}")
        else:
            print(f"> DENY: Subj Curr ({self.subjects[subject]["curr"]}) > Obj Lvl ({self.objects[obj]}) [No Write Down].")
